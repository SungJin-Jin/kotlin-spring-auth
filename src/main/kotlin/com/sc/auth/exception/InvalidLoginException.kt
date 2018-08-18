package com.sc.auth.exception

class InvalidLoginException(val field: String, val error: String) : RuntimeException()
