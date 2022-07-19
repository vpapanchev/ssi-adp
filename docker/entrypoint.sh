#! /bin/sh

gunicorn --preload --workers=2 --timeout 60 -k eventlet -b :${API_PORT} ssi_access_decision_point.__main__:flask_app
