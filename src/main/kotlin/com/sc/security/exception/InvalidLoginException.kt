package com.sc.security.exception

class InvalidLoginException(val field: String, val error: String) : RuntimeException()
