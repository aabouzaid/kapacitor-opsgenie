#!/usr/bin/env python

import ast
import sys
import json
import logging
import requests
import argparse


def logger(log_level, log_file):
    # Init logger.
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    # Create a file handler.
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)

    # Create a logging format.
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handlers to the logger.
    logger.addHandler(handler)

    return logger


def script_arguments(default_team, default_tag):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-t", "--teams", default=default_team,
                        help="OpsGenie teams that will receive the alert.")
    parser.add_argument("-g", "--tags", default=default_tag,
                        help="Alert tags.")
    args = parser.parse_args()
    return args


class opsGenie(object):
    def __init__(self, og_apikey, og_url, og_loglevel, og_logfile):
        self.apikey = og_apikey
        self.url = og_url
        self.loglevel = og_loglevel
        self.logger = logger(og_loglevel, og_logfile)

    def formatPayload(self, json_payload, alert_teams, alert_tags):
        json_dumped = json.dumps(json_payload)
        payload = json.loads(json_dumped)
        teams = alert_teams.split(",")
        tags = alert_tags.split(",")
        formated_details = payload['details'].decode('unicode-escape').strip()
        formated_payload = dict()

        # Main fields.
        formated_payload['apiKey'] = self.apikey
        formated_payload['teams'] = teams
        formated_payload['alias'] = payload['id']
        formated_payload['entity'] = payload['id']
        formated_payload['message'] = payload['message']
        formated_payload['description'] = json.dumps(payload['data'])

        # Extra Fields (can be used for filtering).
        formated_payload['details'] = dict()
        formated_payload['details']['Tags'] = tags
        formated_payload['details']['Level'] = payload['level']
        formated_payload['details']['Monitoring Tool'] = 'Kapacitor'
        formated_payload['details']['Details'] = formated_details

        # Add a note to alert if it recovered.
        if payload['level'] == 'RECOVERY':
            formated_payload['actions'] = 'AddNote,Close'
            formated_payload['note'] = payload['message']
        else:
            formated_payload['actions'] = 'Create'

        return json.dumps(formated_payload)

    def postPayload(self, json_payload):
        payload = json.loads(json_payload)

        # Close the alert if it already recovered.
        if payload['details']['Level'] == 'RECOVERY':
            api_url = self.url + '/close'
        else:
            api_url = self.url

        # Keep OpsGenie API key in debugging.
        if self.loglevel != "DEBUG":
            payload.pop("apiKey")

        self.logger.info('%s', json.dumps(payload))
        return requests.post(api_url, data=json_payload)


# Main.
if __name__ == "__main__":
    # OpsGenie vars.
    ogConfig = {
        "url": "{{ og_url }}",
        "apikey": "{{ og_api_key }}",
        "default": {
            "team": "{{ og_default_team }}",
            "tag": "{{ og_default_tag }}"
        },
        "logging": {
            "file": "{{ og_log_file }}",
            "level": "{{ og_log_level }}"
        }
    }

    # Script vars.
    ogDefault = ogConfig["default"]
    args = script_arguments(ogDefault["team"], ogDefault["tag"])
    alert_teams = args.teams
    alert_tags = args.tags

    # Kapacitor input.
    stdin_input = sys.stdin.readline()
    json_payload = ast.literal_eval(stdin_input)

    # Send output to OpsGenie.
    ogLog = ogConfig["logging"]
    og = opsGenie(ogConfig["apikey"], ogConfig["url"],
                  ogLog["level"], ogLog["file"])
    json_payload = og.formatPayload(json_payload, alert_teams, alert_tags)
    og.postPayload(json_payload)
