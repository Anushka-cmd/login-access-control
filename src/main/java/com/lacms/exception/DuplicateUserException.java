package com.lacms.exception;

/** Thrown when the username or email already exists. */
public class DuplicateUserException extends RuntimeException {
    public DuplicateUserException(String message) {
        super(message);
    }
}
