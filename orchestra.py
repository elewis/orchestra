#!/usr/bin/env python3

import os
import sys
import csv
import random
import signal
import re

import argparse

from fabric.api import env, task, execute, run, parallel, settings, show, hide
env.use_ssh_config = True

def handler_ignore(signal, frame):
	pass

# Ignore Ctrl+C
# signal.signal(signal.SIGINT, handler_ignore)
# Ignore Ctrl+Z
# signal.signal(signal.SIGSTOP, handler_ignore)


@task
@parallel
def exec(command):
	return run(command)

def confirm(message, default_accept=False):
	option = "[Y/n]" if default_accept else "[y/N]"
	prompt = "{message} {option} ".format(message=message, option=option)
	while True:
		answer = input(prompt).lower()
		if not answer:
			return bool(default_accept)
		elif answer.startswith("y"):
			return True
		elif answer.startswith("n"):
			return False

class Shell(object):

	def __init__(self, prompt="$ ", hosts_file="hosts.csv", verbosity=0, accept_all=False, tags=None):
		self._host_manager = HostManager(hosts_file=hosts_file)

		self.prompt 	= prompt
		self.verbosity 	= verbosity
		self.accept_all = accept_all

		if tags is None:
			self.tags = []
		else:
			self.tags = tags

		self.output = {}

		self.builtins = {
			"/help":  self.help,
			"/tag":   self.tag,
			"/hosts": self.host,
			"/exit":  self.exit,
			"/print": self.print,
		}

	def run_forever(self):
		while True:
			try:
				line = input(self.prompt).strip()
				args = line.split()

				if len(args) == 0:
					pass

				elif args[0] in self.builtins:
					self.builtins[args[0]](*args[1:])

				elif args[0].startswith("/"):
					print("{}: command not found".format(args[0]))

				else:
					self.run(" ".join(args))

			except KeyboardInterrupt as e:
				print()

			except Exception as e:
				print("an error occurred: {}".format(str(e)))

	def run(self, command):
		# Validate provided command
		if not command.strip():
			raise ValueError("command cannot be empty")

		# Get all matching hosts
		hosts = self._host_manager.get_hosts(self.tags)

		output_levels = []
		if self.verbosity > 0:
			output_levels.extend(["stdout", "stderr"])
		if self.verbosity > 1:
			output_levels.extend(["debug"])

		with settings(hide("everything"), show(*output_levels), warn_only=True, skip_bad_hosts=True):
			# Return error code if any single host failed
			return self._run_command(command, list(hosts.keys()))

	def _run_command(self, command, hosts, x=1):
		# Run command on n random hosts to test
		random.shuffle(hosts)
		test_results = execute(exec, command, hosts=hosts[:x])
		for host in sorted(test_results.keys()):
			result = test_results[host]
			if isinstance(result, Exception) or result.failed:
				print("failed on test host {host}. aborting".format(host=host))
				return False

		# If successful, run on everything else
		results = execute(exec, command, hosts=hosts[x:])
		results.update(test_results)

		success = True
		for host in sorted(results.keys()):
			result = results[host]
			lines = result.splitlines()

			# Command could not be executed (connection error, permissions, etc)
			if isinstance(result, Exception):
				status = "error ({message})".format(message=str(result))
				color = ("\033[1;31m", "\033[1;m")
				success = False

			# Command was executed but returned an error response
			elif result.failed:
				status = "failed ({return_code})".format(return_code=result.return_code)
				color = ("\033[1;31m", "\033[1;m")
				success = False

			# Command finished successfully
			else:
				status = "success"
				color = ("\033[1;32m", "\033[1;m")

			print("{host:<40} {0}{status:<10}{1} {output}".format(color[0], color[1], host=host, status=status, output=lines[-1].strip()))

		self.output = results

		# Return True if all successful, False otherwise
		return success

	def help(self, *_):
		print("Commands:")
		for command in sorted(self.builtins):
			print("{command:<15}".format(command=command))

	def tag(self, cmd, *tags):

		def usage():
			print("/tag list        - list active tags")
			print("/tag set <*t>    - set full active tags")
			print("/tag add <*t>    - append to active tags")
			print("/tag remove <*t> - remove active tags")

		if not cmd or cmd == "help":
			usage()

		elif cmd == "list":
			for tag in sorted(self.tags):
				print(tag)

		elif cmd == "set":
			self.tags = list(tags)

		elif cmd == "add":
			self.tags.extend(tags)

		elif cmd == "remove":
			for tag in tags:
				try:
					self.tags.remove(tag)
				except ValueError as e:
					# tag not found, don't care
					pass

		else:
			usage()

	def host(self, *_):
		hosts = self._host_manager.get_hosts(self.tags)
		template = "{{host:<{col1}}}\t{{tags}}".format(col1=max(len(h) for h in hosts))
		for host, attrs in sorted(hosts.items()):
			print(template.format(host=host, tags="/".join(sorted(attrs["tags"]))))

	def print(self, *hosts):
		if len(hosts) == 0:
			hosts = list(sorted(self.output.keys()))

		for host in hosts:
			if host in self.output:
				print("  host: {}".format(host))
				print("status: {}".format("not implemented"))
				for line in self.output[host].strip().splitlines():
					print("output: {}".format(line.strip()))
				print()
			else:
				print(" error: unknown host '{}'".format(host))

	def exit(self, status=0, *_):
		print("Goodbye")
		if status:
			sys.exit(status)
		else:
			sys.exit(0)




class HostManager(object):

	TAG_DELIMITER = "|"

	def __init__(self, hosts_file="hosts.csv"):
		self.hosts_file = hosts_file
		self._load_hosts()

	def _load_hosts(self):
		self._hosts = {}
		if not os.path.exists(self.hosts_file):
			raise ValueError('cannot load hosts file ({}), does not exist'.format(self.hosts_file))
		with open(self.hosts_file, "r") as f:
			for row in csv.DictReader(f):
				row["tags"] = row["tags"].split(self.TAG_DELIMITER)
				self._hosts[row["hostname"]] = row

	# Return subset of self._hosts that match ALL given tags
	def get_hosts(self, tags):
		matched_hosts = {}
		for hostname, attrs in self._hosts.items():
			match = True
			for tag in tags:
				if not (tag == hostname or tag in attrs["tags"]):
					match = False
					break
			if match:
				matched_hosts[hostname] = attrs
		return matched_hosts


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--verbose", action="count", default=0)
	parser.add_argument("-y", "--accept-all", action="store_true")
	parser.add_argument("-t", "--tag", help="limit host list to those tagged with this value", type=str, action="append")
	parser.add_argument("command", help="command (with arguments) to run on remote host(s)", nargs=argparse.REMAINDER)
	args = parser.parse_args()

	shell = Shell(verbosity=args.verbose, accept_all=args.accept_all, tags=args.tag)

	if args.command:
		shell.run(" ".join(args.command))
	else:
		shell.run_forever()
