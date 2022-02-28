#!/usr/bin/python3
import os
import re
import itertools

class RuleError(Exception):
	pass

class Ruleset:
	
	def __init__(self, rulefiles):
		self.ruleset = { rule.sid: rule for file in rulefiles for rule in file.rules }

class RulesFile:
	
	def __init__(self, path, text, ignore_errors=True):
		self.path = path
		self.filename = os.path.basename(self.path)
		self.ignore_errors = ignore_errors
		self.rules = self._parse_text(text)

	def _parse_text(self, rule_str):
		rules = []
		lines = []
		count = -1
		for line in rule_str.split('\n'):
			count += 1
			line = line.strip()
			if line.endswith('\\'):
				lines.append(line.rstrip('\\'))
				continue
			else:
				lines.append(line)

			rule_text = ' '.join(lines).strip()

			if not rule_text:
				continue

			try:
				rules.append(Rule(rule_text, filename=self.filename, line_number=count))
			except RuleError:
				pass
			except ValueError as e:
				if not self.ignore_errors:
					raise e

			lines = []

		return rules


_RE_SPLITRULE = re.compile(r'(?<!\\);')
_RE_OPTIONS = re.compile(r'\(.*\)')
_RE_ACTION = re.compile(r'^#? *[\w_]+ ')
_RE_MSG = re.compile(r'msg: *"[^"]+"; ?')
_RE_METADATA = re.compile(r'metadata: *[^;]+; ?')
_RE_CLASSTYPE = re.compile(r'classtype: *[^;]+; ?')
_RE_REFERENCE = re.compile(r'reference: *[^;]+; ?')
_RE_SID = re.compile(r'sid: *[^;]+; ?')
_RE_REV = re.compile(r'rev: *[^;]+; ?')
_RE_PRIORITY = re.compile(r'priority: *[^;]; ?')
class Rule:

	def __init__(self, text, filename=None, line_number=None):
		self.text = text.strip()
		self.filename = filename
		self.line_number = line_number
		self.sid = None
		self.msg = ''
		self.classtype = None
		self.meta = {}
		self.priority = None
		self.action = None
		self.protocol = None
		self.is_commented = self.text.startswith('#')   # flag to check if initially commented

		self._parse_rule()

		options = _RE_OPTIONS.search(self.text).group(0)
		self.options = options

		temp_text = re.sub(_RE_OPTIONS, '', self.text)
		temp_text = re.sub(_RE_ACTION, '', temp_text)
		header = temp_text.strip()

		self.header = header

		temp_text = re.sub(_RE_MSG, '', options)
		temp_text = re.sub(_RE_METADATA, '', temp_text)
		temp_text = re.sub(_RE_CLASSTYPE, '', temp_text)
		temp_text = re.sub(_RE_REFERENCE, '', temp_text)
		temp_text = re.sub(_RE_SID, '', temp_text)
		temp_text = re.sub(_RE_REV, '', temp_text)
		temp_text = re.sub(_RE_PRIORITY, '', temp_text)

		self.detectors = temp_text


	def __hash__(self):
		return hash(self.sid)

	def _parse_rule(self):

		try:
			parts = self.text.lstrip('# ').split(None, 7)

			(self.action, self.protocol, self.src_ip, self.src_port,
			self.direction, self.dst_ip, self.dst_port, meta) = parts
		except ValueError:
			raise RuleError(f'Cannot parse: {self.text}')

		meta_parts = _RE_SPLITRULE.split(meta)
		for kv in meta_parts:
			if ':' in kv:
				key, raw_value = kv.lstrip('( ').split(':', 1)
				#value = raw_value.strip().strip('"')
				value = raw_value.strip()
				if value.startswith('"'):
					value = value[1:]
				if value.endswith('"'):
					value = value[:-1]

				if key in ['flowbits', 'metadata', 'content', 'reference', 'pcre']:
					if key not in self.meta:
						self.meta[key] = []
					self.meta[key].append(value)
				else:
					self.meta[key] = value

		if 'sid' not in self.meta:
			raise ValueError(f'Rule missing "sid": {self.text}')

		self.sid = self.meta['sid']
		self.msg = self.meta.get('msg', '')
		self.rev = self.meta.get('rev', '0')
		self.priority = self.meta.get('priority')
		self.classtype = self.meta.get('classtype', None)
		self.references = self.meta.get('reference', [])
		self.metadata = self.meta.get('metadata', [])

		# if rule was initially commented
		self.is_commented = self.text.startswith('#')

	def __repr__(self):
		return '<Rule: {self.sid}:{self.rev}, msg:{self.msg!r}>'.format(self=self)

	@property
	def is_disabled(self):
		return self.text.startswith('#')

	@property
	def is_enabled(self):
		return not self.is_disabled

	@property
	def is_deleted(self):
		return 'deleted' in self.filename

	@property
	def is_in_testing(self):
		return 'testing' in self.filename

	@property
	def is_active(self):
		return not self.is_deleted and self.is_enabled and not self.is_in_testing
