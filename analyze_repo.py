#!/usr/bin/python3
import collections
import git
import io
import os
import re
import time
import itertools
import json
import sys
from rules import *


##########################
##########################
## REPLACE VALUES BELOW ##
##########################
##########################

repo = git.Repo('path/to/git/repo')				# path to git rule repo (local)
dir_paths = [ 'path/to/rule/dir', ]				# path to the directory that contains .rules files
destination_file = 'path/to/outputfile.json'	# JSON file
branch = 'master'

def analyze_repo():
	rules = collections.defaultdict(list)

	try:
		repo.git.checkout(branch)
	except repo.exc.GitCommandError:
		print(f'Branch "{branch}" does not exist. Exiting.')
		sys.exit(1)

	new_rules = None
	commit_hash = None
	date = None
	author = None
	for i, commit in enumerate(repo.iter_commits(branch)):
		files = []
		added = {}
		deleted = {}
		edited = {}

		for blob in commit.tree.traverse():
			for dp in dir_paths:
				if blob.path.startswith(dp) and blob.path.endswith('.rules'):
					files.append(blob.path)

		all_rules = []

		for file in files:
			targetfile = commit.tree / file
			try:
				with io.BytesIO(targetfile.data_stream.read()) as f:
					rule_file_text = f.read().decode('utf-8')
			except:
				try:
					print('\ndecoding failure at %s for file %s' % (commit.binsha.hex(), targetfile.path))
					with io.BytesIO(targetfile.data_stream.read()) as f:
						rule_file_text = f.read().decode('cp1252')
				except:
					print('\ndecoding failure at %s for file %s' % (commit.binsha.hex(), targetfile.path))
					with io.BytesIO(targetfile.data_stream.read()) as f:
						rule_file_text = f.read().decode('utf-16')

			rule_file = RulesFile(path=targetfile.path, text=rule_file_text)
			all_rules.append(rule_file)


		old_rules = Ruleset(all_rules).ruleset

		if new_rules is not None:
			
			for sid in old_rules.keys() & new_rules.keys():
				new_rule = new_rules[sid]
				old_rule = old_rules[sid]

				mod = {
					'sid': sid,
					'rev': new_rule.rev,
					'priority': new_rule.priority,
					'classtype': new_rule.classtype,
					'text': new_rule.text,
					'action': new_rule.action,
					'header': new_rule.header,
					'detectors': new_rule.detectors,
					'date': date,
					'author': author,
					'commit_hash': commit_hash,
					'filename': new_rule.filename,
					'type': '',
				}

				origin = ''
				if old_rule.is_in_testing:
					origin = 'T'
				elif not old_rule.is_active:
					origin = 'D'
				else:
					origin = 'P'

				destination = ''
				if new_rule.is_in_testing:
					destination = 'T'
				elif not new_rule.is_active:
					destination = 'D'
				else:
					destination = 'P'

				if new_rule.action != old_rule.action:
					mod['type'] += 'X'

				if new_rule.header != old_rule.header:
					mod['type'] += 'Y'

				if new_rule.detectors != old_rule.detectors:
					mod['type'] += 'Z'


				if old_rule.is_deleted and not new_rule.is_deleted:
					mod['type'] += 'U'


				if mod['type'] != '':
					mod['type'] += '-%s%s' % (origin, destination)
					edited[sid] = mod
				else:
					if origin != destination:
						mod['type'] += 'N-%s%s' % (origin, destination)
						edited[sid] = mod
					else:
						if new_rule.options != old_rule.options:
							mod['type'] += 'O-%s%s' % (origin, destination)
							edited[sid] = mod


			for sid in new_rules.keys() - old_rules.keys():
				new_rule = new_rules[sid]

				mod = {
					'sid': sid,
					'rev': new_rule.rev,
					'priority': new_rule.priority,
					'classtype': new_rule.classtype,
					'text': new_rule.text,
					'action': new_rule.action,
					'header': new_rule.header,
					'detectors': new_rule.detectors,
					'date': date,
					'author': author,
					'commit_hash': commit_hash,
					'filename': new_rule.filename,
					'type': 'A',
				}

				if new_rule.is_in_testing:
					mod['type'] += 'T'

				if new_rule.is_disabled or new_rule.is_deleted:
					mod['type'] += 'D'

				if new_rule.is_active:
					mod['type'] += 'P'

				added[sid] = mod

			for sid in old_rules.keys() - new_rules.keys():
				old_rule = old_rules[sid]
				origin = ''
				if old_rule.is_in_testing:
					origin = 'T'
				elif not old_rule.is_active:
					origin = 'D'
				else:
					origin = 'P'

				mod = {
					'sid': sid,
					'rev': old_rule.rev,
					'priority': old_rule.priority,
					'classtype': old_rule.classtype,
					'text': old_rule.text,
					'action': old_rule.action,
					'header': old_rule.header,
					'detectors': old_rule.detectors,
					'date': date,
					'author': author,
					'commit_hash': commit_hash,
					'filename': old_rule.filename,
					'type': 'R-%s' % origin,
				}

				deleted[sid] = mod


			# add to database
			for sid, mod in added.items():
				rules[sid].append(mod)

			for sid, mod in deleted.items():
				rules[sid].append(mod)

			for sid, mod in edited.items():
				rules[sid].append(mod)

		new_rules = old_rules
		date = time.strftime('%d/%m/%Y %H:%M', time.gmtime(commit.authored_date))
		commit_hash = commit.binsha.hex()
		author = commit.author.email

	# process first commit
	for sid, rule in old_rules.items():
		mod = {
			'sid': sid,
			'rev': rule.rev,
			'priority': rule.priority,
			'classtype': rule.classtype,
			'text': rule.text,
			'action': rule.action,
			'header': rule.header,
			'detectors': rule.detectors,
			'date': date,
			'author': author,
			'commit_hash': commit_hash,
			'filename': rule.filename,
			'type': 'A',
		}

		if rule.is_in_testing:
			mod['type'] += 'T'

		if rule.is_disabled or rule.is_deleted:
			mod['type'] += 'D'

		if rule.is_active:
			mod['type'] += 'P'

		rules[sid].append(mod)

	return rules

def main():
	rules = analyze_repo()

	with open(destination_file, 'w') as file:
		file.write(json.dumps(rules, indent=4))

if __name__ == '__main__':
	main()
