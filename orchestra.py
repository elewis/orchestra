#!/usr/bin/env python3

import os
import sys
import csv
import random

import argparse

from fabric.api import env, task, execute, run, parallel, settings, show, hide
env.use_ssh_config = True


def get_hosts(*tags):
	"""
	Return list of hostnames that match any of the given tags.
	"""
	hosts = []
	with open("hosts.csv", "r") as f:
		for row in csv.DictReader(f):
			for tag in tags:
				if tag == row["hostname"] or tag in row["tags"].split("|"):
					hosts.append(row["hostname"])
					break
	return list(sorted(hosts))

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

def confirm_command(command, hosts):
	print("Running:")
	print(command)
	print()
	print("On the following hosts:")
	for hostname in hosts:
		print(hostname)
	print()

	answer = confirm("Proceed?", default_accept=False)
	print()
	return answer

def run_command(command, hosts, n=1):
	# Run command on n random hosts to test
	random.shuffle(hosts)
	test_results = execute(exec, command, hosts=hosts[:n])
	for host in sorted(test_results.keys()):
		result = test_results[host]

		if isinstance(result, Exception) or result.failed:
			print("test failed on {host}. aborting".format(host=host))
			return False

	# If successful, run on everything else
	results = execute(exec, command, hosts=hosts[n:])
	results.update(test_results)

	success = True
	for host in sorted(results.keys()):
		result = results[host]

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

		print("{host:<40} {0}{status}{1}".format(color[0], color[1], host=host, status=status))

	# Return True if all successful, False otherwise
	return success

@task
@parallel
def exec(command):
	return run(command)


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-v", "--verbose", action="count", default=0)
	parser.add_argument("-y", "--accept-all", action="store_true")
	parser.add_argument("-t", "--tag", help="limit host list to those tagged with this value", type=str, action="append", required=True)
	parser.add_argument("command", help="command (with arguments) to run on remote host(s)", nargs=argparse.REMAINDER)
	args = parser.parse_args()

	# Validate provided command
	command = " ".join(args.command)
	if not command.strip():
		print("error: command cannot be empty")
		sys.exit(1)

	# Get all matching hosts
	hosts = get_hosts(*args.tag)

	output_levels = []
	if args.verbose > 0:
		output_levels.extend(["stdout", "stderr"])
	if args.verbose > 1:
		output_levels.extend(["debug"])

	if args.accept_all or confirm_command(command, hosts):
		with settings(hide("everything"), show(*output_levels), warn_only=True, skip_bad_hosts=True):
			# Return error code if any single host failed
			if run_command(command, hosts):
				sys.exit(0)
			else:
				sys.exit(1)

	else:
		print("Aborting")
