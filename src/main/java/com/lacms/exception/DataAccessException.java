package com.lacms.exception;

/** Unchecked wrapper for SQLException so service code stays readable. */
public class DataAccessException extends RuntimeException {
    public DataAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
