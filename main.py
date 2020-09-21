#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps
from pathlib import Path
from secrets import token_bytes
from struct import pack, unpack
from subprocess import PIPE, run
from sys import exit
from uuid import uuid4
from zlib import compress, decompress

from cryptography.hazmat.primitives.hashes import Hash, BLAKE2b

from utilities import CipherContext, RotatingCipherContext


class BlackMamba:
	def __init__(self, repository, secrets, password):
		self._repository = Path(repository)
		self._secrets = Path(secrets)
		self._password = password
		self._check_requirements()

	def _check_requirements(self):
		if not check_for_git():
			raise FileNotFoundError('Git is not installed on the system!')

	def _rebuild_index(self):
		index = {}
		cipher = CipherContext(self._password)

		for path in self._secrets.glob('*.secret'):
			with open(path, 'rb') as file:
				contents = file.read()

			plaintext = decompress(cipher.decrypt(contents))

			# We extract the path out of the plaintext first.
			path_size = unpack('>H', plaintext[:2])[0]
			short_path = plaintext[2:path_size + 2].decode()

			# This is the true plaintext.
			plaintext = plaintext[path_size + 2:]

			# We need to generate a hash for the file.
			hasher = Hash(BLAKE2b(64))
			hasher.update(plaintext)

			index[short_path] = {
				'path': short_path,
				'uuid': path.stem,
				'checksum': hasher.finalize().hex()
			}

		return index

	def _build_index(self):
		index = {}

		for path in get_git_files(self._repository):
			if (self._repository / path).is_file():
				uuid = str(uuid4())

				while index.get(uuid):
					uuid = str(uuid4())

				hasher = Hash(BLAKE2b(64))

				with open(self._repository / path, 'rb') as file:
					hasher.update(file.read())

				index[str(path)] = {
					'path': str(path),
					'uuid': uuid,
					'checksum': hasher.finalize().hex()
				}

		for path in (self._repository / '.git').glob('**/*'):
			if path.is_file():
				uuid = str(uuid4())

				while index.get(uuid):
					uuid = str(uuid4())

				hasher = Hash(BLAKE2b(64))

				with open(path, 'rb') as file:
					hasher.update(file.read())

				short_path = path.relative_to(self._repository)

				index[str(short_path)] = {
					'path': str(short_path),
					'uuid': uuid,
					'checksum': hasher.finalize().hex()
				}

		return index

	def _build_changes(self):
		rebuilt_index = self._rebuild_index()
		index = self._build_index()
		paths = {*rebuilt_index.keys(), *index.keys()}
		additions = []
		updates = []
		removals = []
		# unchanged = []

		for path in paths:
			if path in index and path not in rebuilt_index:
				additions.append(index[path])
			elif path in rebuilt_index and path not in index:
				removals.append(rebuilt_index[path])
			elif index[path]['checksum'] != rebuilt_index[path]['checksum']:
				# print(index[path]['checksum'], '!=', rebuilt_index[path]['checksum'])
				updates.append(index[path])
			# else:
			# 	unchanged.append(index[path])

		return {
			'additions': additions,
			'updates': updates,
			'removals': removals
		}

	def encrypt(self):
		if not self._repository.is_dir():
			raise NotADirectoryError('There is no repository at the supplied path!')

		if not check_for_repository(self._repository):
			raise FileNotFoundError('There is no Git repository in that directory!')

		if not self._secrets.is_dir():
			print('[i] Creating the secrets directory...')
			self._secrets.mkdir()

		changes = self._build_changes()
		cipher = RotatingCipherContext(self._password)

		if changes['additions'] or changes['updates']:
			print('[i] Generating encryption keys...')
			cipher.generate_keys()

		# We first process any additions to the repository.
		print('[i] Processing additions and updates...')
		for change in changes['additions'] + changes['updates']:
			try:
				with open(self._repository / change['path'], 'rb') as file:
					contents = file.read()
			except FileNotFoundError:
				print_objects('[-] A file was not found (and has not been encrypted):', change)
				continue

			header = pack('>H', len(change['path'])) + change['path'].encode()

			with open(self._secrets / (change['uuid'] + '.secret'), 'wb') as file:
				file.write(cipher.encrypt(compress(header + contents)))

		# We can now remove any missing entries.
		print('[i] Processing removed secrets...')
		for change in changes['removals']:
			(self._secrets / (change['uuid'] + '.secret')).unlink()

	def decrypt(self):
		if not self._secrets.is_dir():
			raise NotADirectoryError('There are no secrets at the supplied path!')

		if not self._repository.is_dir():
			print('[i] Creating the repository directory...')
			self._repository.mkdir()

		print('[i] Initializing the Git repository...')
		run_cli('git init', cwd=self._repository)
		cipher = CipherContext(self._password)

		print('[i] Processing secrets...')
		for path in self._secrets.glob('*.secret'):
			with open(path, 'rb') as file:
				contents = file.read()

			plaintext = decompress(cipher.decrypt(contents))

			# We extract the path out of the plaintext first.
			path_size = unpack('>H', plaintext[:2])[0]
			short_path = plaintext[2:path_size + 2].decode()

			# This is the true plaintext.
			plaintext = plaintext[path_size + 2:]

			# We first ensure no path-traversal exploits.
			if self._repository.resolve() not in (self._repository / short_path).resolve().parents:
				print_objects('[-] A path tried to escape its sandbox (and has not been decrypted):', {
					'path': short_path,
					'uuid': path.stem
				})
				continue

			# We can now create the parent directories.
			(self._repository / Path(short_path).parent).mkdir(parents=True, exist_ok=True)

			with open(self._repository / short_path, 'wb') as file:
				file.write(plaintext)

	def view(self):
		if not self._secrets.is_dir():
			raise NotADirectoryError('There are no secrets at the supplied path!')

		print_objects('[+] Here is a rebuilt index:', self._rebuild_index())


def print_objects(*args):
	printables = []

	for argument in args:
		if isinstance(argument, dict):
			printables.append(dumps(argument, sort_keys=True, indent='\t'))
		else:
			printables.append(argument)

	print(*printables)


def run_cli(command, *args, **kwargs):
	return run(command, *args, shell=True, stdout=PIPE, **kwargs).stdout.decode()


def get_git_files(path):
	return [
		Path(line) \
		for line in run_cli('git ls-files --cached --others --exclude-standard', cwd=path).split('\n') \
		if line
	]


def check_for_git():
	try:
		return run_cli('git --version').startswith('git version')
	except FileNotFoundError:
		return False


def check_for_repository(path):
	return run_cli('git status', cwd=path) != ''


def main():
	parser = ArgumentParser(description='Converts the target Git repository into secrets.')
	parser.add_argument('--password', help='The password to use for any operations.', required=True)
	parser.add_argument('--repository', help='The path for the repository folder.', default='.')
	parser.add_argument('--secrets', help='The path for the secrets folder.', default='secrets')
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('--encrypt', help='Flag that converts the repository into secrets.', action='store_true')
	group.add_argument('--decrypt', help='Flag that converts the secrets into a repository.', action='store_true')
	group.add_argument('--view', help='Flag that shows the metadata of secrets.', action='store_true')
	arguments = parser.parse_args()

	context = BlackMamba(
		repository=arguments.repository,
		secrets=arguments.secrets,
		password=arguments.password
	)

	if arguments.encrypt:
		print('[i] Starting encryption operation...')
		context.encrypt()
	elif arguments.decrypt:
		print('[i] Starting decryption operation...')
		context.decrypt()
	elif arguments.view:
		print('[i] Starting view operation...')
		context.view()

	print('[+] The operation completed successfully.')


if __name__ == '__main__':
	main()
