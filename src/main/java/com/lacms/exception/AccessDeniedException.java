package com.lacms.exception;

/** Thrown when the acting user lacks the permission for an operation. */
public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String message) {
        super(message);
    }
}
