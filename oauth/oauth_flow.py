import os, base64, json, quopri, requests
import imaplib, smtplib, email, ssl, webbrowser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from email.header import decode_header
from urllib.parse import urlencode, quote, unquote
from urllib.request import urlopen
from .models import GmailAccount
import pytz, logging, codecs
from bs4 import BeautifulSoup
from .utils.parse_dates import date_parser
from decouple import config


logger = logging.getLogger(__name__)
GOOGLE_ACCOUNTS_BASE_URL = "https://accounts.google.com"
# REDIRECT_URI = "https://oauth2.dance/"
REDIRECT_URI = "http://127.0.0.1:8000/oauth/oauth_code/"
REDIRECT_URI2 = "http://127.0.0.1:8000/"
SCOPE = "https://mail.google.com/"
LAGOS_TIMEZONE = pytz.timezone("Africa/Lagos")

class GmailOAuthHandler:
    def __init__(self):
        self.client_id = config("GMAIL_CLIENT_ID")
        self.client_secret = config("GMAIL_CLIENT_SECRET")

    def store_tokens(self, user:str, gmail_address:str, token_data:dict):
        try:
            gmail_account, created = GmailAccount.objects.get_or_create(
                user=user,
                defaults={
                    "gmail_address": gmail_address,
                }
            )
            gmail_account.access_token = token_data.get("access_token")
            gmail_account.refresh_token = token_data.get("refresh_token")
            gmail_account.expires_at = datetime.fromtimestamp(
                datetime.now().timestamp() + token_data["expires_in"]
            ).replace(microsecond=0)
            gmail_account.save()
            print("GMAIL_ACCOUNT_INSTANCE::::::", gmail_account, "\n\n\n\n\n")
            print("Sales Officer Gmail Profile saved successfully!", created, "\n\n\n\n\n")
            return {
                "user": gmail_account.user,
                "gmail_address": gmail_account.gmail_address,
                "access_token": gmail_account.access_token,
                "refresh_token": gmail_account.refresh_token,
            }
        except Exception as e:
            return {
                "message": "An error occurred while attempting to save gmail instance!",
                "error": str(e)
            }
        
    def save_auth_code(self, gmail_address:str, authorization_code:str):
        gmail_account = GmailAccount.objects.update(
            gmail_address=gmail_address,
            authorization_code=authorization_code,
        )
    
    def get_valid_token(self, gmail_address:str):
        try:
            gmail_account = GmailAccount.objects.get(gmail_address=gmail_address)
        except GmailAccount.DoesNotExist:
            raise ValueError("User has not authenticated!")
        
        try:
            if datetime.now().astimezone() > gmail_account.expires_at - timedelta(minutes=1):
                new_token = self.refresh_access_tokens(gmail_address)
                return new_token
        except Exception as e:
            return str(e)
        return gmail_account.access_token

    def get_authorization_url(self, gmail_address:str, scope=SCOPE):
        params = {
            "client_id": self.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "response_type": "code",
            "access_type": "offline",
            "prompt": "consent",
            "state": gmail_address,
        }
        return f"{GOOGLE_ACCOUNTS_BASE_URL}/o/oauth2/auth?{urlencode(params)}"
        
    def fetch_tokens(self, authorization_code:str):
        token_url = f"{GOOGLE_ACCOUNTS_BASE_URL}/o/oauth2/token"
       
        data = {
            "code": authorization_code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": REDIRECT_URI2,
            "grant_type": "authorization_code",
        }
        response = urlopen(token_url, data=urlencode(data).encode()).read()

        token_data = json.loads(response)

        return token_data
    
    def refresh_access_tokens(self, gmail_address:str):
        try:
            gmail_account = GmailAccount.objects.get(gmail_address=gmail_address)
        except GmailAccount.DoesNotExist:
            raise ValueError("User has not authenticated!")
        
        token_url = f"{GOOGLE_ACCOUNTS_BASE_URL}/o/oauth2/token"

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": gmail_account.refresh_token,
            "grant_type": "refresh_token",
        }
        response = urlopen(token_url, data=urlencode(data).encode()).read()
        new_token_data = json.loads(response)
        new_access_token = new_token_data["access_token"]
        expiry_date = new_token_data["expires_in"]

        new_expiry_date = datetime.fromtimestamp(
            datetime.now().timestamp() + expiry_date, tz=LAGOS_TIMEZONE
        ).replace(microsecond=0)
        
        GmailAccount.objects.update(
            gmail_address=gmail_address,
            access_token=new_access_token,
            expires_at=new_expiry_date,
        )
        return new_access_token

    def get_oauth2_string(self, gmail_address:str):
        access_token = self.get_valid_token(gmail_address)
        auth_string = f"user={gmail_address}\1auth=Bearer {access_token}\1\1"
        # auth_string = f"user={gmail_address}\x01auth=Bearer {access_token}\x01\x01"
        # return base64.b64encode(auth_string.encode("utf-8")).decode()
        return auth_string
    
    def get_b64_oauth2_string(self, gmail_address:str):
        access_token = self.get_valid_token(gmail_address)
        auth_string = f"user={gmail_address}\1auth=Bearer {access_token}\1\1"
        # auth_string = f"user={gmail_address}\x01auth=Bearer {access_token}\x01\x01"
        return base64.b64encode(auth_string.encode("utf-8")).decode()
        # return auth_string
    
    def clean(self, text):
        return "".join(c if c.isalnum() else "_" for c in text)
    
    def retrieve_google_mails(self, gmail_address:str):
        oauth2_string = self.get_oauth2_string(gmail_address)
        imap_conn = imaplib.IMAP4_SSL("imap.gmail.com", ssl_context=ssl.create_default_context())
        imap_conn.debug = 4
        imap_conn.authenticate("XOAUTH2", lambda x: oauth2_string.encode())
        status, messages = imap_conn.select("INBOX")
        typ, data = imap_conn.search(None, "ALL")
        emails = []

        try:
            for i in data[0].split():
                res, msg_data = imap_conn.fetch(i, "(RFC822)")
                # uid_response = imap_conn.uid()
                # emails.append(uid_response)
                msg = email.message_from_bytes(msg_data[0][1])
                email_message = msg.as_string()

                gmail_date = msg['Date']
                email_date = date_parser(gmail_date, "%Y-%m-%d %H:%M:%S%z")
                email_sender = msg['From']
                email_subject = msg['Subject']
                receiver_email = msg['To']
                cc = msg['Cc']
                bcc = msg['Bcc']

                if '<' in email_sender:
                    sender_name = email_sender.split('<')[0].strip()
                else:
                    sender_name = email_sender

                text_content = ""

                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()

                        if content_type == 'text/html' or content_type == 'text/plain':
                            payload = part.get_payload(decode=True)

                            if content_transfer_encoding == 'quoted-printable':
                                byte_payload = bytes(payload)
                                payload = byte_payload.decode("latin-1")
                            elif content_transfer_encoding == 'base64':
                                byte_payload = bytes(payload)
                                payload = codecs.decode(byte_payload, "utf-8")
                            else:
                                payload = payload.decode("utf-8")

                            # Parsing the HTML part
                            if content_type == 'text/html':
                                soup = BeautifulSoup(payload, 'html.parser')
                            else: 
                                text_content = payload
                            break
                else:
                    # For non-multipart emails, decode payload directly
                    payload = msg.get_payload(decode=True)
                    content_transfer_encoding = msg.get('Content-Transfer-Encoding', '').lower()

                    if content_transfer_encoding == 'quoted-printable':
                        try:
                            payload = quopri.decodestring(payload).decode('utf-8')
                        except UnicodeDecodeError:
                            continue

                        text_content = payload

                line = "-" * 100
                emails.append(
                    {
                        # "EMAIL": msg.as_string(),
                        "date": email_date,
                        "subject": email_subject,
                        "sender": email_sender,
                        "sender_name": sender_name,
                        "cc": cc,
                        "bcc": bcc,
                        "receiver": receiver_email,
                        "content": text_content,
                        "-": line,
                    }
                )

            sorted_emails = sorted(emails, key=lambda x: x['date'] if x['date'] else '')

            mails_box = []

            for mail in sorted_emails:
                line = '-' * 40
                mail_box = {
                    "Date": {mail["date"]},
                    "Subject": {mail["subject"]},
                    "Sender": {mail["sender"]},
                    "Senders_Name": {mail["sender_name"]},
                    "Cc": {mail["cc"]},
                    "Bcc": {mail["bcc"]},
                    "Receiver": {mail["receiver"]},
                    "Content": {mail["content"]},
                }

                mails_box.append(mail_box)
            
            # imap_conn.close()
            # imap_conn.logout()
            # return mails_box
        except Exception as e:
            return ("AN ERROR OCCURRED WHILE ATTEMPTING TO RETRIEVE\n", str(e))

        finally:
            # for response in msg:
            #     if isinstance(response, tuple):
            #         msg = email.message_from_bytes(response[1])
            #         subject, encoding = decode_header(msg["Subject"])[0]
            #         if isinstance(subject, bytes):
            #             subject = subject.decode(encoding)
                    
            #         From, encoding = decode_header(msg.get("From"))[0]
            #         if isinstance(From, bytes):
            #             From = From.decode(encoding)
            #         emails.append(subject)
            #         emails.append(From)
            #         print("EMAILS::::::", emails, "\n\n\n\n\n")

            #         # For multipart mails
            #         if msg.is_multipart():
            #             for part in msg.walk():
            #                 content_type = part.get_content_type()
            #                 content_disposition = str(part.get("Content-Disposition"))
            #                 try:
            #                     body = part.get_payload(decode=True).decode()
            #                 except:
            #                     pass

            #                 if content_type == "text/plain" and "attachment" not in content_disposition:
            #                     print(body)
            #                 elif "attachment" in content_disposition:
            #                     file_name = part.get_filename()
            #                     if file_name:
            #                         folder_name = self.clean(subject)
            #                         if not os.path.isdir(folder_name):
            #                             os.mkdir(folder_name)
            #                         file_path = os.path.join(folder_name, file_name)
            #                         open(file_path, "wb").write(part.get_payload(decode=True))
            #         else:
            #             content_type = msg.get_content_type()
            #             body = msg.get_payload(decode=True).decode()
            #             if content_type == "text/plain":
            #                 print(body)
            #         if content_type == "text/html":
            #             folder_name = self.clean(subject)
            #             if not os.path.isdir(folder_name):
            #                 if not os.path.isdir(folder_name):
            #                     os.mkdir(folder_name)
            #                 file_name = "index.html"
            #                 file_path = os.path.join(folder_name, file_name)
            #                 open(file_path, "w").write(body)
            #         print("-"*100)
            imap_conn.close()
            imap_conn.logout()

            return mails_box
    
    def send_google_mails(self, gmail_address:str, recipient_email:list, subject:str, cc:str, bcc:str, message:str,):
        oauth2_string = self.get_b64_oauth2_string(gmail_address)
        smtp_conn = smtplib.SMTP_SSL("smtp.gmail.com", context=ssl.create_default_context())
        smtp_conn.set_debuglevel(1)
        
        try:
            smtp_conn.ehlo()
            status = smtp_conn.docmd("AUTH", "XOAUTH2 " + oauth2_string)
            if status[0] != 235:
                raise smtplib.SMTPAuthenticationError(status[0], status[1].decode())
            
            msg = MIMEMultipart('alternative')
            msg['From'] = gmail_address
            msg['To'] = ", ".join(recipient_email)
            msg['subject'] = subject
            msg['Cc'] = ", ".join(cc)
            msg['Bcc'] = ", ".join(bcc)

            # Plain text and html versions for emails
            text = f"{message}"
            html = f"<html><body>{message}</body></html>"
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)

            smtp_conn.sendmail(gmail_address, recipient_email, msg.as_string())
            smtp_conn.quit()


            print("CONNECTION_STATUS::::::", status[0], "\n\n\n\n\n")
            return {
                "status": status[0],
            }
        except smtplib.SMTPException as e:
            return {
                "message": "An error occurred while attempting to send email",
                "error": str(e),
            }    