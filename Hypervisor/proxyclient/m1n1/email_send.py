from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from .email_sensitive_config import email_uesr, email_passwd
def sendMail(message,Subject,sender_show,recipient_show,to_addrs,cc_show=''):

    user = email_uesr
    password = email_passwd

    msg = MIMEText(message, 'plain', _charset="utf-8")

    msg["Subject"] = Subject

    msg["from"] = sender_show

    msg["to"] = recipient_show

    msg["Cc"] = cc_show

    with SMTP_SSL(host="",port=465) as smtp:
        try:
            # 
            smtp.login(user = user, password = password)
            # 
            smtp.sendmail(from_addr = user, to_addrs=to_addrs.split(','), msg=msg.as_string())
            print("send complete, plz check the sent box")
        except Exception as e:
            print(e)
