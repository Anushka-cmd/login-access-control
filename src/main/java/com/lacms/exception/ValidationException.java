package com.lacms.exception;

/** Thrown when user input (username, email, password, role...) is invalid. */
public class ValidationException extends RuntimeException {
    public ValidationException(String message) {
        super(message);
    }
}
