#!/usr/bin/python3

# this file is part of shus.
#
# Copyright (c) 2015 Dima Krasner
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import urllib.request
import http.client
import socket
import threading
import queue
import logging
import random
import re
import sys

SERVER = (sys.argv[1], int(sys.argv[2]))
TIMEOUT = 5
THREADS = 64
ITERATIONS = 4096
MAX_REPLY_SIZE = 1024 * 1024

VALID_REQUESTS = (b"GET / HTTP/1.1\r\n", b"GET /shusd HTTP/1.1\r\n")
BAD_METHOD_REQUESTS = (
	b"POST /missing HTTP/1.1\r\n",
	b"CONNECT /missing HTTP/1.1\r\n",
	b"\xff\xff\xff\xff /missing HTTP/1.1\r\n"
)
MISSING_REQUESTS = (b"GET /missing HTTP/1.1\r\n", )
NO_URL_REQUESTS = (b"GET HTTP/1.1\r\n", )
RELATIVE_URL_REQUESTS = (
	b"GET . HTTP/1.1\r\n",
	b"GET ./missing HTTP/1.1\r\n"
	b"GET .. HTTP/1.1\r\n",
	b"GET ../missing HTTP/1.1\r\n"
	b"GET ./ HTTP/1.1\r\n",
	b"GET ../ HTTP/1.1\r\n",
	b"GET /. HTTP/1.1\r\n",
	b"GET /./ HTTP/1.1\r\n",
	b"GET /.. HTTP/1.1\r\n",
	b"GET /../ HTTP/1.1\r\n",
	b"GET /./missing HTTP/1.1\r\n"
	b"GET /../missing HTTP/1.1\r\n"
)
BAD_REQUESTS = (
	b"GET missing HTTP/1.1\r\n",
	b"\xf1\xf2\xf3\xf4\xf5\xf6",
	b"GET",
	b"GET ",
	b"GET /",
	b" ",
	b"\0",
	b"\0\0\0\0",
	b"\0\0\0\0 /",
	b"\0\0\0\0\0\0\0\0",
	b"\xf1\xf2\xf3\xf4\xf5\xf6" * 1024
)
EMPTY_REQUESTS = ("", )

HEADERS_PATTERN = "HTTP/1.1 200 OK\r\n" \
                "Connection: close\r\n" \
                "Date: \d+/\d+/\d+ \d+:\d+:\d+\r\n" \
                "Content-Type: .*/.*\r\n" \
                "(Content-Length: \d*\r\n)*" \
                "\r\n" \
                ".*"

class PunishmentException(Exception):
	pass

class NoReplyException(Exception):
	pass

class InvalidReplyException(Exception):
	pass

class NoExceptionException(Exception):
	pass

class Test(object):
	def __init__(self, name, requests, raises):
		self.name = name
		self.requests = list(requests)
		random.shuffle(self.requests)
		self.raises = raises

	def verify(self, reply):
		if 0 == len(reply):
			raise NoReplyException()

		try:
			index = reply.index(bytes("\r\n\r\n", "ascii"))
			headers = reply[:4 + index].decode("ascii")
		except (ValueError, UnicodeDecodeError):
			raise PunishmentException()

		if re.match(HEADERS_PATTERN, headers) is None:
			raise InvalidReplyException()

	def _run_once(self, request):
		s = socket.socket()

		try:
			s.settimeout(TIMEOUT)
			s.connect(SERVER)
			if 0 < len(request):
				s.send(request)
			self.verify(s.recv(MAX_REPLY_SIZE))
		except self.raises as exception:
			logging.info("caught %s" % type(exception).__name__)
			return
		except Exception as exception:
			logging.exception(
			               "unhandled exception: %s" % type(exception).__name__)
			raise
		finally:
			s.close()

		if 0 != len(self.raises):
			logging.error("no exception raised")
			raise NoExceptionException()

	def run(self):
		logging.info("running a test: %s" % self.name)
		s = socket.socket()

		for request in self.requests:
			self._run_once(request)

def worker(q):
	try:
		while True:
			q.get().run()
			q.task_done()
	except queue.Empty:
		pass

logging.basicConfig(level = logging.DEBUG)

q = queue.Queue()
tests = ITERATIONS * [
	Test("valid request", VALID_REQUESTS, ()),
	Test("bad method", BAD_METHOD_REQUESTS, (PunishmentException, )),
	Test("missing file", MISSING_REQUESTS, (NoReplyException, )),
	Test("blank URL", NO_URL_REQUESTS, (PunishmentException, )),
	Test("relative URL", RELATIVE_URL_REQUESTS, (PunishmentException, )),
	Test("empty request", EMPTY_REQUESTS, (socket.timeout, )),
	Test("bad request", BAD_REQUESTS, (PunishmentException, )),
]
random.shuffle(tests)

for test in tests:
	q.put(test)

for i in range(THREADS):
	t = threading.Thread(target = worker, args = (q, ))
	t.daemon = True
	t.start()

q.join()
