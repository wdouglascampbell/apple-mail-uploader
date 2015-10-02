#!/usr/bin/python
'''
 '  Copyright 2015 Doug Campbell
 '
 '  This program is free software: you can redistribute it and/or modify
 '  it under the terms of the GNU General Public License as published by
 '  the Free Software Foundation, either version 3 of the License, or
 '  (at your option) any later version.
 '
 '  This program is distributed in the hope that it will be useful,
 '  but WITHOUT ANY WARRANTY; without even the implied warranty of
 '  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 '  GNU General Public License for more details.
 '
 '  You should have received a copy of the GNU General Public License
 '  along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import apiclient
import BaseHTTPServer
import email.utils
import getopt
import httplib2
import io
import logging
import mailbox
import md5
import os
import platform
import random
import re
import simplejson
import sqlite3
import sys
import time
import urllib
import webbrowser

from apiclient import errors
from collections import defaultdict
from credentials import *
from googleapiclient.discovery import build
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import OAuth2Credentials
from oauth2client import GOOGLE_AUTH_URI
from oauth2client import GOOGLE_REVOKE_URI
from oauth2client import GOOGLE_TOKEN_URI
from urlparse import urlparse, parse_qs

# turn on logging
logging.basicConfig(filename='apple-mail-uploader.log',level=logging.INFO)

# configure needed Google Scopes
SCOPES = ("https://www.googleapis.com/auth/gmail.modify",)

# 32 backspaces
BS32 = "\b"*32

# disable output buffering on OS X
class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

sys.stdout = Unbuffered(sys.stdout)

# get UUID used by Apple Mail for current user
conn = sqlite3.connect(os.path.expanduser('~') + "/Library/Mail/V2/MailData/Envelope Index")
c = conn.cursor()
c.execute("select value from properties where key='UUID';")
UUID = c.fetchone()[0]
conn.close()

# get OS X major version
v, _, _ = platform.mac_ver()
osx_version = tuple(map(int, (v.split("."))))


"""
 * parseCommandLine
 *
 * Parses the command line to see if either the --reauth or --redoallmessages
 * switches are used.
 *
 * Returns:
 *     True/False values for reauth and redoall
 *
"""
def parseCommandLine():
    # parse command line arguments
    # apple-mail-uploader.py [--reauth] [--redoallmessages] [--help]
    reauth = False
    redoall = False
    options, remainder = getopt.getopt(sys.argv[1:], "", ['help', 'reauth', 'redoallmessages'])
    for opt in options:
        if '--help' in opt:
            print
            print "Usage: apple-mail-uploader.py [--reauth] [--redoallmessages]"
            print "       apple-mail-uploader.py [--help]"
            print
            print "       --help            : displays this message"
            print "       --reauth          : forces reauthorization"
            print "       --redoallmessages : migrated message database entries will be cleared for"
            print "                         : the mailbox being migrated so that all messages will be"
            print "                         : attempted to migrate again."
            print
            sys.exit()
        if '--reauth' in opt:
            reauth = True
        if '--redoallmessages' in opt:
            redoall = True
    return reauth,redoall

"""
 * getUserLabels
 *
 * Get a list all labels in account.
 *
 * Args:
 *     service: Authorized Gmail API service instance.
 *     user_id: Account email address. The special value "me"
 *              can be used to indicate the authenticated user.
 *
 * Returns:
 *     A list all labels in account.
"""
def getUserLabels(service, user_id):
    labels = {}

    try:
        response = service.users().labels().list(userId=user_id).execute()
        labelsList = response['labels']
        for label in labelsList:
            if label['type'] == "user":
                labels[label['name']] = label['id']
    except errors.HttpError, error:
        logging.error('function getUserLabels: An error occurred: %s' % error)
        print 'An error occurred: %s' % error

    return labels

"""
 * createLabel
 *
 * Create a new label for account.
 *
 * Args:
 *     service: Authorized Gmail API service instance.
 *     user_id: Account email address. The special value "me"
 *              can be used to indicate the authenticated user.
 *     label_object: label object for label to be added.
 *
 *  Returns:
 *     Label ID
"""
def createLabel(service, user_id, label_object):
    try:
        label = service.users().labels().create(userId=user_id,
                                                body=label_object).execute()
        #print 'Label created for folder: %s' % label_object['name']
        print("Label created for folder: {0}".format((label_object['name'].ljust(55,' ')[:53] + '..') if len(label_object['name'].ljust(55,' ')) > 55 else label_object['name'].ljust(55,' ')))
        #print("Folder: {0} ".format((label.ljust(55,' ')[:53] + '..') if len(label.ljust(55,' ')) > 55 else label.ljust(55,' ')))
        return label['id']
    except errors.HttpError, error:
        logging.error('function createLabel: An error occurred: %s' % error)
        print 'An error occurred: %s' % error

"""
 * makeLabel
 *
 * Create label object.
 *
 * Args:
 *     label_name: The name of the Label.
 *     mlv: Message list visibility, show/hide.
 *     llv: Label list visibility, labelShow/labelHide.
 *
 * Returns:
 *    Created Label.
"""
def makeLabel(label_name, mlv='show', llv='labelShow'):
    label = {'messageListVisibility': mlv,
             'name': label_name,
             'labelListVisibility': llv}
    return label

"""
 * checkAddLabel
 *
 * If not exists, add label.
 *
 * Args:
 *     service: Authorized Gmail API service instance.
 *     label: label name
 *     current_labels: list of current labels for account
 *
"""
def checkAddLabel(service, label, current_labels):
    if label not in current_labels:
        current_labels[label] = createLabel(service,'me',makeLabel(label))

"""
 * getMigrateMessageInfo
 *
 * Retrieves message info (message-id, google id) from database for messages
 * that have already been migrated from this mailbox.
 *
 * Args:
 *     conn: database connection handler
 *     mailbox : mailbox associated with messages
 *     redoall: indicates whether to remove all message info and migrate all messages again
 *
 * Returns:
 *     message info list
"""
def getMigrateMessageInfo(conn,mailbox,redoall):
    c = conn.cursor()

    # does message_info table exist?
    message_info = {}
    c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?", ["table", "message_info"])
    if c.fetchone()[0] > 0:
        # message_info table exists, retrieve message-id and google id values
        if redoall:
            c.execute("DELETE FROM message_info where mailbox = ?", [mailbox])
            conn.commit()
        c.execute("SELECT * FROM message_info where mailbox = ?", [mailbox])
        while True:
            row = c.fetchone()
            if row is None:
                break
            message_info[row[1]] = row[2]
    else:
        # create table
        c.execute("CREATE TABLE message_info (mailbox text, message_id text, google_id text, UNIQUE (mailbox, message_id))")
        conn.commit()

    return message_info

"""
 * getLabelsByMessage
 *
 * Retrieves the list of labels that for each message of the given account mailroot
 *
 * Args:
 *     mailroot : path to account's root mail folder
 *
 * Returns:
 *     dictionary containing each message's label list
"""
def getLabelsByMessage(mailroot):
    global system_labels

    label_list = defaultdict(list)
    conn = sqlite3.connect(os.path.expanduser('~') + "/Library/Mail/V2/MailData/Envelope Index")
    c = conn.cursor()
    base_url = re.sub(r'^.*?(IMAP|POP)-(.*)$',lambda match: r'{}://{}'.format(match.group(1).lower(),match.group(2)),mailroot)
    query = "SELECT labels.message_id, mailboxes.url FROM labels INNER JOIN mailboxes ON labels.mailbox_id=mailboxes.ROWID WHERE url LIKE ?"
    for row in c.execute(query,[base_url + "%"]):
        label_part = urllib.unquote(row[1].replace(base_url + "/","")).decode('utf8')
        if label_part in system_labels:
            label_part = system_labels[label_part]
        label_list[row[0]].append(label_part)
    conn.close()
    return label_list

"""
 * processLabelsForGmailImapAccount
 *
 * Iterates through the Apple Mail folders for the given account and creates a label in Gmail if it doesn't already exist.
 *
 * Args:
 *     service:  authorized Gmail API service instance.
 *     mailroot: path to account's root mail folder
 *     folder: folder to check/add label for
 *
 * Returns:
 *     dictionary containing each message's label list
"""
def processLabelsForGmailImapAccount(service,mailroot,folder):
    global current_labels

    # build label
    label = folder.replace(mailroot + '/','').replace('.mbox','')

    # add label if it doesn't exist
    checkAddLabel(service, label, current_labels)

    # list mbox folders
    current, dirs, files = os.walk(folder).next()
    mbox_folders = [dir for dir in dirs if dir.endswith(".mbox") ]

    for mbox_folder in mbox_folders:
        processLabelsForGmailImapAccount(service,mailroot,folder + "/" + mbox_folder)

"""
 * getAuthCredentials
 *
 * Gets a credentials object that can be used to authorize a service object
 *
 * Args:
 *     conn: database connection handler
 *     reauth: indicates whether to remove all message-id and migrate all messages again
 *
"""
def getAuthCredentials(conn,reauth):
    c = conn.cursor()

    # does config table exist?
    c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?", ["table", "config"])
    if c.fetchone()[0] > 0:
        # config table exists, retrieve refresh_token if it exists
        c.execute("SELECT * FROM config WHERE name='refresh_token'")
        result = c.fetchone()
    else:
        result = None

    # retrieve refresh token, if one exists
    if result is None or reauth:
        # no refresh token.  need to get authorized.

        # get user authorization URL
        flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, " ".join(SCOPES), redirect_uri="http://127.0.0.1:8000")
        auth_uri = flow.step1_get_authorize_url()

        print("\nLaunching your preferred web browser to continue sign-in at")
        print("your account provider website.  When you have granted access,")
        print("please return here to continue.")

        # open authorization url in preferred browser
        webbrowser.open(auth_uri)

        # start mini-webserver to listen for auth code response
        httpd = BaseHTTPServer.HTTPServer(('127.0.0.1', 8000), CustomHandler)
        httpd.handle_request()

        if auth_code:
            # retrieve authorization credentials using auth code
            credentials = flow.step2_exchange(auth_code)
            refresh_token = credentials.refresh_token
            print("\n\nAuthorization completed.\n")
        else:
            print("\nNo authorization code!")
            logging.info('Authorization Failed!')
            sys.exit("Exiting...")

        # create `config` table
        conn.execute("CREATE TABLE IF NOT EXISTS config (name text unique, value text)")

        # insert refresh_token into `config` table
        conn.execute("INSERT OR REPLACE INTO config (name, value) VALUES ('refresh_token','{0}')".format(refresh_token))

        # save changes
        conn.commit()
    else:
        refresh_token = result[1]
        credentials = OAuth2Credentials(None, CLIENT_ID,
                                   CLIENT_SECRET, refresh_token, None,
                                   GOOGLE_TOKEN_URI, None,
                                   revoke_uri=GOOGLE_REVOKE_URI,
                                   id_token=None,
                                   token_response=None)

    return credentials

'''
 * processMailbox
 *
 * Retrieves list of mbox folders and determines type of account associated with mailbox.
 *
 * For Gmail accounts, it...
 *
 * For normal accounts, it iterates through the mbox folder list and processes the folders.
 *
 * Args:
 *     service:  authorized Gmail API service instance.
 *     mailroot: path of mailbox root folder
 *     message_info: message-id and google id for all migrated messages
 *     conn: database connection handle
 *
'''
def processMailbox(service,mailroot,message_info,conn):
    global osx_version
    
    # initial total messages and total failed messages counts
    total_messages = 0
    total_failed = 0

    # list mbox folders
    current, dirs, files = os.walk(mailroot).next()
    mbox_folders = [dir for dir in dirs if dir.endswith(".mbox") ]

    if 'Drafts.mbox' in mbox_folders:
        # Gmail API cannot handle import of messages to Drafts folder
        del mbox_folders[mbox_folders.index('Drafts.mbox')]
    
    if 'Deleted Messages.mbox' in mbox_folders:
        # Ignore already deleted messages
        del mbox_folders[mbox_folders.index('Deleted Messages.mbox')]
    
    if 'Outbox.mbox' in mbox_folders:
        # Ignore unsent messages
        del mbox_folders[mbox_folders.index('Outbox.mbox')]
    
    # is this OS X version prior to 10.9?
    if "[Gmail].mbox" in mbox_folders and osx_version < [10,9]:
        # remove [Gmail].mbox folder so it can be processed like non-Gmail IMAP accounts
        del mbox_folders[mbox_folders.index("[Gmail].mbox")]
        
    # does "[Gmail].mbox" folder exists?
    if "[Gmail].mbox" in mbox_folders:
        # yes (Gmail account)
        # create labels if they don't already exist
        del mbox_folders[mbox_folders.index("[Gmail].mbox")]
        for folder in mbox_folders:
            folder_path = mailroot + "/" + folder
            processLabelsForGmailImapAccount(service,mailroot,folder_path)
        
        # get labels for each message to be migrated
        labels_list = getLabelsByMessage(mailroot)
        
        if uuidFolderExists("%s/[Gmail].mbox/All Mail.mbox" % (mailroot)):
            # output some feedback
            logging.info("Migrating all mail...")
            print("Migrating all messages for this Gmail IMAP account")
            print(" *                                "),
            
            # migrate messages
            total_messages, total_failed = migrateGmailImapMessages(service,mailroot,labels_list,message_info,conn)
    else:
        # no (normal account)
        for folder in mbox_folders:
            folder_path = mailroot + "/" + folder
            number_messages, number_failed = processMboxFolder(service,mailroot,folder_path,message_info,conn)
            total_messages += number_messages
            total_failed += number_failed
            
    return total_messages, total_failed

'''
 * processMboxFolder
 *
 * Creates label for folder if it doesn't already exist.
 * Retrieves list of immediate sub-folders and processes them recursively using this function
 * Migrates all messages in folder.
 *
 * Args:
 *     service:  authorized Gmail API service instance
 *     mailroot: path of mailbox root folder
 *     folder:   path of folder to process
 *     message_info: message-id and google id for all migrated messages
 *     conn: database connection handle
 *
'''
def processMboxFolder(service,mailroot,folder,message_info,conn):
    global current_labels, UUID

    # initial total messages and total failed messages counts
    total_messages = 0
    total_failed = 0

    # build label
    label = folder.replace(mailroot + '/','').replace('.mbox','')

    # add label if it doesn't exist
    checkAddLabel(service, label, current_labels)

    # list mbox folders
    current, dirs, files = os.walk(folder).next()
    mbox_folders = [dir for dir in dirs if dir.endswith(".mbox") ]

    for mbox_folder in mbox_folders:
        number_messages, number_failed = processMboxFolder(service,mailroot,folder + "/" + mbox_folder,message_info,conn)
        total_messages += number_messages
        total_failed += number_failed
    if uuidFolderExists(folder):
        # output some feedback
        logging.info("Migrating folder: {0}".format(label))
        print("Folder: {0} ".format((label.ljust(55,' ')[:53] + '..') if len(label.ljust(55,' ')) > 55 else label.ljust(55,' ')))
        print(" *                                "),
        
        number_messages, number_failed = migrateMessages(service,mailroot,folder + "/" + UUID + "/Data/Messages",current_labels[label],message_info,conn)
        total_messages += number_messages
        total_failed += number_failed

    return total_messages, total_failed

'''
 * uuidFolderExists
 *
 * Checks whether mbox folder contains a folder named with this user account's Mail UUID.
 *
 * Args:
 *     folder: path of mbox folder
 *
'''
def uuidFolderExists(folder):
    global UUID

    return (os.path.isdir(folder + '/' + UUID + '/Data/Messages'))

'''
 * extractMsg
 *
 * Extracts full e-mail message contained in the emlx file.
 *
 * Args:
 *     emlx_file: full path to .emlx or .partial.emlx file
 *
'''
def extractMsg(emlx_file):
    f = open(emlx_file, 'r')
    first_line = f.readline()
    msg_length = int(first_line)
    msg_content = f.read(msg_length)
    f.close()
    return msg_content

'''
 * getMsgSections
 *
 * Returns a list of all main message sections from given message
 *
 * Args:
 *     msg: message
 *     boundary: boundary separation string
 *
'''
def getMsgSections(msg,boundary):
    # initialize sections
    sections = []

    boundary_end = msg.find("--"+boundary,0)
    while boundary_end != -1:
        boundary_begin = boundary_end
        boundary_end = msg.find("--"+boundary,boundary_begin+1)

        if boundary_end != -1:
            sections.append(msg[boundary_begin+len(boundary)+3:boundary_end])

    return sections

'''
 * isSectionLacksBody
 *
 * Checks if section body content needs to be added from .emlxpart file
 *
 * Args:
 *     content: section content
 *
'''
def isSectionLacksBody(content):
   # get value of X-Apple-Content-Length header
   appleContentLength = re.search("^X-Apple-Content-Length: (\d+)", content, re.MULTILINE)
   if appleContentLength is None:
       return False

   # is X-Apple-Content-Length non-zero?
   if len(appleContentLength.group(1)) > 1:
       # get content body size
       end_of_headers = content.find("\n\n")
       body_size = len("".join(content[end_of_headers:].split()))
       return (body_size == 0)
   else:
       return False

'''
 * is MsgRead
 *
 * Retrieves read status of message
 *
 * Args:
 *     emlx_file: path to message file
 *
'''
def isMsgRead(emlx_file):
    filename = emlx_file[emlx_file.rfind('/')+1:]
    row_id = filename[0:filename.find('.')]
    conn = sqlite3.connect(os.path.expanduser('~') + "/Library/Mail/V2/MailData/Envelope Index")
    c = conn.cursor()
    c.execute("SELECT read FROM messages WHERE ROWID = ?",[row_id])
    read_status = c.fetchone()[0]
    conn.close()
    
    return (read_status == "1")

'''
 * getMailMessageForUpload
 *
 * Retrieves mail message from given file and includes sections found in other files
 *
 * Args:
 *     file: file containing emlx message
 *
'''
def getMailMessageForUpload(file):
    # get message contents from emlx file
    msg = extractMsg(file)

    # get message-id
    message_id = re.search("^Message-ID: (.*?)$", msg, re.MULTILINE | re.IGNORECASE).group(1)
    
    # get message subject
    message_subject = re.search("^Subject: (.*?)$", msg, re.MULTILINE | re.IGNORECASE).group(1)
    
    # get boundary string
    boundary_search = re.search("^Content-Type:.*?boundary=\"?(.*?)\"?$", msg, re.MULTILINE | re.DOTALL)
    if boundary_search is None:
        # pure text message has no boundaries
        return message_id, message_subject, msg
    else:
        boundary = boundary_search.group(1)

    # get message header
    end_of_header = msg.find("--"+boundary,0)
    header = msg[0:end_of_header]

    # begin building new message parts
    msg_parts = [header]

    # get message sections
    sections = getMsgSections(msg,boundary)

    for index, section in enumerate(sections):
        # add section content to new message parts
        msg_parts.extend(["--",boundary,"\n",section])

        if isSectionLacksBody(section):
            # get .emlxpart file content for this section
            emlxpart_file = file[0:file.rfind('.partial.emlx')] + "." + str(index+1) + ".emlxpart"
            f = open(emlxpart_file, 'r')
            emlxpart_content = f.read()
            f.close()

            # add .emlxpart content to new message parts
            msg_parts.extend([emlxpart_content,"\n"])

    # add last boundary to new message parts
    msg_parts.extend(["--",boundary,"--"])

    # return message-id and full message string
    return message_id, message_subject, "".join(msg_parts)

'''
 * migrateGmailImapMessages
 *
 * Migrates messages from Gmail Imap storage to GMail.
 *
 * Args:
 *     service: authorized Gmail API service instance
 *     mailroot: path of mailbox root folder
 *     labels_list: list of labels for this message
 *     message_info: message-id and google id for all migrated messages
 *     conn: database connection handle
 *
'''
def migrateGmailImapMessages(service,mailroot,labels_list,message_info,conn):
    global current_labels, UUID
    
    # get list all .emlx files
    folder = "%s/[Gmail].mbox/All Mail.mbox/%s/Data/Messages" % (mailroot,UUID)
    emlx_files = [ folder + "/" + file for file in os.listdir(folder) if file.endswith(".emlx") ]
    
    # get total number of .emlx files (messages) in folder
    total_messages = len(emlx_files)

    # initialize number of failed messages
    total_failed = 0

    # iterate over all messages in folder
    msg_number = 0
    for emlx_file in emlx_files:
        msg_number += 1
        print(BS32+"Migrating message: {0} of {1}".format(str(msg_number).zfill(4),str(total_messages).zfill(4))),

        # get file name
        filename = emlx_file[emlx_file.rfind('/')+1:]
        filenum = filename[:filename.find('.')]
        
        # initialize labels
        # one label will always be 'CATEGORY_PERSONAL'
        # one label will be 'UNREAD' if the message being uploaded has yet to be read
        # the remaining labels will be based on the labels associated with this message from the sqlite3 database
        labels = ['CATEGORY_PERSONAL']
        for label in labels_list[int(filenum)]:
            labels.append(current_labels[label])

        # is message marked UNREAD?
        if not isMsgRead(emlx_file):
            labels.append("UNREAD")
        
        # get message
        message_id, message_subject, msg = getMailMessageForUpload(emlx_file)
    
        # has message already been uploaded
        if message_id in message_info:
            # Yes.
            # Check if current label is listed for this message
            try:
                response = service.users().messages().get(userId='me', id=message_info[message_id], format='minimal').execute()
                msg_labels = response['labelIds']
                missing_labels = [item for item in labels if item not in msg_labels]
                if missing_labels:
                    # Some label(s) are not set for this message.  Add missing label(s).
                    try:
                        label_modifications = {'addLabelIds': missing_labels, 'removeLabelIds': []}
                        response = service.users().messages().modify(userId='me', id=message_info[message_id],
                                                                     body=label_modifications).execute()
                        logging.info("Message %s of %s - Added missing labels: %s" % (msg_number,total_messages,', '.join(missing_labels)))
                        continue
                    except errors.HttpError, error:
                        logging.info("Message %s of %s - Error adding missing labels: %s - Error: %s" %
                                      (msg_number,total_messages,', '.join(missing_labels),error))
                        continue
                    
                # Message has already been uploaded and no labels need to be added. Skip it.
                logging.info("Message {0} of {1} - Already Uploaded - Skipped".format(msg_number,total_messages))
                continue
            except errors.HttpError, e:
                error = simplejson.loads(e.content)
                if error['error']['code'] == 404:
                    # Message already uploaded but has been deleted manually
                    logging.info("Message %s of %s - Already Uploaded and Manually Deleted - Skipped" % (msg_number,total_messages))
                continue
        
        # create file object to stream message contents
        fh = io.BytesIO(msg)

        # create media upload object
        media = apiclient.http.MediaIoBaseUpload( fh, mimetype='message/rfc822', chunksize=1024*1024, resumable=True )

        # import message
        postBody = { "labelIds": labels }

        # create import message request object
        request = service.users().messages().import_(userId='me', body=postBody, media_body=media, internalDateSource=None,
                                                     neverMarkSpam=True, processForCalendar=None, deleted=None)

        # upload message in resumable chunks
        response = None
        upload_failed = False
        while response is None:
            try:
                status, response = request.next_chunk()
            except KeyboardInterrupt:
                print "\n\nUser ended execution"
                sys.exit()
            except:
                upload_failed = True
                total_failed += 1
                logging.error("Message {0} of {1} - Upload Failed!".format(msg_number,total_messages))
                break

        if not upload_failed:
            conn.execute("INSERT into message_info VALUES (?,?,?)", [mailroot,message_id,response['id']])
            conn.commit()
            message_info[message_id]=response['id']
            logging.info('Message {0} of {1} - "{2}"- Upload Complete'.format(msg_number,total_messages,message_subject))

        # close BaseIO object
        fh.close()
        
    print "\r",

    return total_messages, total_failed

'''
 * migrateMessages
 *
 * Migrates messages to GMail.
 *
 * Args:
 *     service: authorized Gmail API service instance
 *     mailroot: path of mailbox root folder
 *     folder: path to mbox folder containing messages to migrate
 *     label: label id to assign to messages
 *     message_info: message-id and google id for all migrated messages
 *     conn: database connection handle
 *
'''
def migrateMessages(service,mailroot,folder,label,message_info,conn):
    # get list all .emlx files
    emlx_files = [ folder + "/" + file for file in os.listdir(folder) if file.endswith(".emlx") ]
    
    # get total number of .emlx files (messages) in folder
    total_messages = len(emlx_files)

    # initialize number of failed messages
    total_failed = 0

    # iterate over all messages in folder
    msg_number = 0
    for emlx_file in emlx_files:
        msg_number += 1
        print(BS32+"Migrating message: {0} of {1}".format(str(msg_number).zfill(4),str(total_messages).zfill(4))),

        # initialize labels
        # one label will always be 'CATEGORY_PERSONAL'
        # one label will be based on the label provided
        # one label will be 'UNREAD' if the message being uploaded has yet to be read
        labels = ['CATEGORY_PERSONAL', label]

        # is message marked UNREAD?
        if not isMsgRead(emlx_file):
            labels.append("UNREAD")
        
        # get message
        message_id, message_subject, msg = getMailMessageForUpload(emlx_file)
    
        # has message already been uploaded
        if message_id in message_info:
            # Yes.
            # Check if current label is listed for this message
            try:
                response = service.users().messages().get(userId='me', id=message_info[message_id], format='minimal').execute()
                msg_labels = response['labelIds']
                if label not in msg_labels:
                    # Current label not set for this message.  Add it.
                    try:
                        label_modifications = {'addLabelIds': [label], 'removeLabelIds': []}
                        response = service.users().messages().modify(userId='me', id=message_info[message_id],
                                                                     body=label_modifications).execute()
                        logging.info("Message %s of %s - Added new label ID of %s" % (msg_number,total_messages,label))
                        continue
                    except errors.HttpError, error:
                        logging.info("Message %s of %s - Error adding new Label ID of %s - Error: %s" %
                                      (msg_number,total_messages,label,error))
                        continue
                    
                # Message has already been uploaded and no labels need to be added. Skip it.
                logging.info("Message {0} of {1} - Already Uploaded - Skipped".format(msg_number,total_messages))
                continue
            except errors.HttpError, e:
                error = simplejson.loads(e.content)
                if error['error']['code'] == 404:
                    # Message already uploaded but has been deleted manually
                    logging.info("Message %s of %s - Already Uploaded and Manually Deleted - Skipped" % (msg_number,total_messages))
                continue
        
        # create file object to stream message contents
        fh = io.BytesIO(msg)

        # create media upload object
        media = apiclient.http.MediaIoBaseUpload( fh, mimetype='message/rfc822', chunksize=1024*1024, resumable=True )

        # import message
        postBody = { "labelIds": labels }

        # create import message request object
        request = service.users().messages().import_(userId='me', body=postBody, media_body=media, internalDateSource=None,
                                                     neverMarkSpam=True, processForCalendar=None, deleted=None)

        # upload message in resumable chunks
        response = None
        upload_failed = False
        while response is None:
            try:
                status, response = request.next_chunk()
            except KeyboardInterrupt:
                print "\n\nUser ended execution"
                sys.exit()
            except:
                upload_failed = True
                total_failed += 1
                logging.error("Message {0} of {1} - Upload Failed!".format(msg_number,total_messages))
                break

        if not upload_failed:
            conn.execute("INSERT into message_info VALUES (?,?,?)", [mailroot,message_id,response['id']])
            conn.commit()
            message_info[message_id]=response['id']
            logging.info('Message {0} of {1} - "{2}"- Upload Complete'.format(msg_number,total_messages,message_subject))

        # close BaseIO object
        fh.close()
        
    print "\r",

    return total_messages, total_failed
        
"""
 * CustomHandler class
 *
 * Modify base HTTP server to receive Google auth code and notify
 * user whether the authorization was successful.
 *
"""
class CustomHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code

        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            auth_code = query_components['code'][0]
            response = "You may now close the browser tab and switch back to the application."
        else:
            auth_code = None
            response = "Authorization failed!"

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)

    # redefine log_message to prevent output to console log
    def log_message(self, format, *args):
        return

# parse command line arguments
reauth, redoall = parseCommandLine()

# open apple-mail-uploader database
try:
    conn = sqlite3.connect('apple-mail-uploader.db')
except sqlite3.Error:
    print "Error opening db.\n"

# get authorized credentials
credentials = getAuthCredentials(conn,reauth)

# Create an httplib2.Http object to handle our HTTP requests and authorize it
# with the credentials.
http = httplib2.Http()
http = credentials.authorize(http)

# get Gmail API service object
service = build('gmail', 'v1', http=http)

# get list of current labels
current_labels = getUserLabels(service, 'me')
current_labels["DRAFTS"] = "DRAFTS"
current_labels["Drafts"] = "DRAFTS"
current_labels["INBOX"] = "INBOX"
current_labels["Inbox"] = "INBOX"
current_labels["Incoming"] = "INBOX"
current_labels["SENT"] = "SENT"
current_labels["IMPORTANT"] = "IMPORTANT"
current_labels["SPAM"] = "SPAM"
current_labels["STARRED"] = "STARRED"
current_labels["TRASH"] = "TRASH"

# set list of system labels
system_labels = {'[Gmail]/Drafts' : u'DRAFTS', '[Gmail]/Important' : u'IMPORTANT', '[Gmail]/Sent Mail' : u'SENT', '[Gmail]/Spam' : u'SPAM', '[Gmail]/Starred' : u'STARRED', '[Gmail]/Trash' : u'TRASH'}

# Set to Apple Mail Storage Location
APPLE_MAIL_STORAGE_LOCATION = os.path.expanduser('~') + '/Library/Mail/V2'

# Get list of folder entries in Apple Mail Storage Location
current, dirs, files = os.walk(APPLE_MAIL_STORAGE_LOCATION).next()

# Filter out "MailData" and "RSS" to obtain available account folder choices
account_folders = [ dir for dir in dirs if dir not in ["MailData","RSS"] ]

if len(account_folders) > 1:
    # display account folders selection menu
    print("Please select the number of the account folder to migrate:")

    # list available account folders
    selection = 0
    while not (selection > 0 and selection <= n):
        n = 0
        for account_folder in account_folders:
            n += 1
            if account_folder == "Mailboxes":
                folder_label = "Local Mail"
            else:
                folder_label = account_folder
            print("{0} : {1}".format(str(n).rjust(2),folder_label))
        try:
            selection = int(raw_input("Selection: "))
            if selection > 0 and selection <= n:
                selected_account_folder = account_folders[selection-1]
            else:
                print("Invalid selection!  Please try again.")
        except:
            print("Invalid selection!  Please try again.")
else:
    selected_account_folder = account_folders[0]

account_folder_location = APPLE_MAIL_STORAGE_LOCATION + '/' + selected_account_folder

print("\nBeginning migration...\n")

# get message information for this mailbox's already migrated messages
message_info = getMigrateMessageInfo(conn,account_folder_location,redoall)

# process mailbox
total_messages, total_failed = processMailbox(service,account_folder_location,message_info,conn)

# close database connection
conn.close()

print("\r                                  ")
print("Migration Complete.\n")
print("Total # of Messages Processed: {0}".format(total_messages))
if total_failed > 0:
    print("There were {0} messages that had errors during processing.  See log file for details.\n".format(total_failed))
else:
    print("There were no errors in processing.\n")

raw_input("Press Enter to close application...")

sys.exit("Exiting...")
