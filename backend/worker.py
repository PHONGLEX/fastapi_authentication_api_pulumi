import asyncio

from celery import Celery
from celery.utils.log import get_task_logger
from celery.decorators import task

from helper.config import config
from helper.email_helper import send_mail

celery = Celery(__name__)
logger = get_task_logger(__name__)

celery.conf.broker_url = config['CELERY_BROKER_URL']

@task(name="send_email_task")
def send_email_task(data):
    print(data)
    asyncio.get_event_loop().run_until_complete(send_mail(data))