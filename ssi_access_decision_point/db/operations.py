import json
import logging
import random

from multiprocessing import Lock
from pathlib import Path

lock = Lock()
FILE_PATH = "db.requests.json"


def init_database():
  logging.info('Initializing Requests Database file: Waiting to acquire lock')
  lock.acquire()
  try:
    if not Path(FILE_PATH).exists():
      Path(FILE_PATH).touch()
      logging.info('Created Requests Database file: {}'.format(FILE_PATH))
    else:
      logging.info('Requests Database file already created.')
  finally:
    logging.info('Releasing lock')
    lock.release()


def __read_requests():
  with open(FILE_PATH) as f:
    try:
      requests = json.load(f)
    except json.decoder.JSONDecodeError:
      requests = []
  return requests


def __write_requests(requests):
  with open(FILE_PATH, 'w') as f:
    json.dump(requests, f)


def __save_new_request(request):
  requests = __read_requests()
  requests.append(request)
  __write_requests(requests)


def store_new_user_request(sender, resource_url, http_request_method, presentation_request):
  request = {
    "id": str(random.randint(100000000000000, 100000000000000000)),
    "sender": sender,
    "resource_url": resource_url,
    "http_request_method": http_request_method,
    "presentation_request": presentation_request
  }
  lock.acquire()
  try:
    __save_new_request(request)
  finally:
    lock.release()
  return request


def get_user_requests(sender):
  lock.acquire()
  try:
    requests = __read_requests()
  finally:
    lock.release()
  user_requests = []
  for req in requests:
    if req["sender"] == sender:
      user_requests.append(req)
  return user_requests


def delete_user_request(request_id):
  lock.acquire()
  try:
    requests = __read_requests()
    new_requests = []
    for req in requests:
      if req["id"] != request_id:
        new_requests.append(req)
    __write_requests(new_requests)
  finally:
    lock.release()
