import os
import slack
import json
from pprint import pprint
from _datetime import datetime
from collections import OrderedDict


SMART_CHECK_REPORT = '/tmp/report.txt'
SMART_CHECK_URL = os.environ['SMART_CHECK_URL']
SLACK_CHANNEL_NAME = os.getenv('SLACK_CHANNEL_NAME')
SLACK_API_TOKEN = os.getenv('SLACK_API_TOKEN')


class SmartCheck:
    def __init__(self, sc_url, report_file):
        self.results = self._json_results(report_file)
        self.sc_url = sc_url

    @staticmethod
    def _json_results(input_filename):
        print(f'Retrieving report from {input_filename}')
        with open(input_filename, 'r') as f:
            output = json.load(f)
            pprint(output)

        return output

    def extract_data(self):
        print('\nExtracting data from report...')

        output = dict()
        output['metadata'] = OrderedDict()

        repo = self.results['source']['repository']
        tag = self.results['source']['tag']
        image = f'{repo}:{tag}'
        print(f'Image: {image}')
        output['metadata']['Image'] = image

        for entry in ['started', 'requested', 'completed']:
            entry_capital = entry.capitalize()
            ts = self.results['details'][entry]
            print(f'{entry}: {ts}')
            output['metadata'][entry_capital] = ts

        started_dt = datetime.strptime(output['metadata']['Started'], "%Y-%m-%dT%H:%M:%SZ")
        completed_dt = datetime.strptime(output['metadata']['Completed'], "%Y-%m-%dT%H:%M:%SZ")

        duration = completed_dt - started_dt
        output['metadata']['Scan Duration'] = duration

        scan_link = self.results['href']
        if scan_link.startswith('/api/'):
            scan_link = scan_link[4:]

        registry = self.results['source']['registry']
        print(f'Registry: {registry}')
        output['metadata']['Registry'] = registry

        full_link = f'{self.sc_url}{scan_link}'
        print(f'Scan link: {full_link}')
        output['metadata']['Scan Link'] = full_link

        findings = self.results['findings']
        findings.pop('scanners')

        for parent_entry in findings:
            if parent_entry == 'malware':
                malware_count = findings['malware']
                print(f'Malware count: {malware_count}')
                output['Malware'] = malware_count

                continue

            sub_entries = findings[parent_entry]['unresolved']

            # Skip entries with no unresolved issues
            if not sub_entries:
                continue

            category = parent_entry.capitalize()
            output[category] = dict()

            print(f'\nExtracting {parent_entry} data:')

            for severity, severity_count in sub_entries.items():
                severity_name = severity.capitalize()
                output[category][severity_name] = severity_count
                print(f'{severity_name}: {severity_count}')

        return output


class SlackClient:
    def __init__(self, smart_check_report, pipeline_channel):
        self.sc = slack.WebClient(token=SLACK_API_TOKEN)
        self.pipeline_channel_id = self._get_channel_id(pipeline_channel)
        self._send_report(smart_check_report)

    def _get_channel_id(self, pipeline_channel):
        get_channels = self.sc.api_call('channels.list')
        for channel in get_channels['channels']:
            if channel['name'] == pipeline_channel:
                channel_id = channel['id']

                return channel_id

    def _send_report(self, smart_check_report):
        banner_sep = '#' * 25
        sub_banner_sep = '~' * 20
        build_msg = [
            banner_sep,
            ':exclamation: *Insecure Image Detected* :exclamation:',
            banner_sep,

        ]

        for key, value in smart_check_report['metadata'].items():
            build_msg.append(f'*{key}:* {value}')

        build_msg.append('\n')
        del smart_check_report['metadata']

        for key, value in smart_check_report.items():
            if isinstance(key, str) and key == 'Malware':
                malware_msg = [
                    sub_banner_sep,
                    '*Malware:*',
                    sub_banner_sep,
                    f'*Items*: {value}',
                    '',
                ]

                join_malware_msg = '\n'.join(malware_msg)
                build_msg.append(join_malware_msg)

            elif isinstance(value, dict):
                vuln_msg = [
                    sub_banner_sep,
                    f'*{key}:*',
                    sub_banner_sep,
                ]

                for severity_name, count in value.items():
                    vuln_msg.append(f'*{severity_name}*: {count}')

                vuln_msg.append('')
                join_vuln_msg = '\n'.join(vuln_msg)
                build_msg.append(join_vuln_msg)

        msg = '\n'.join(build_msg)

        self.sc.chat_postMessage(
            channel=self.pipeline_channel_id,
            text=msg,
            type='mrkdwn'
        )


def main():
    # extract data
    smart_check = SmartCheck(SMART_CHECK_URL, SMART_CHECK_REPORT)
    smart_check_report = smart_check.extract_data()

    # integrations
    if SLACK_CHANNEL_NAME and SLACK_API_TOKEN:
        SlackClient(smart_check_report, SLACK_CHANNEL_NAME)

    else:
        print('\nSlack inputs not provided. Skipping Slack integration.')


if __name__ == '__main__':
    main()
