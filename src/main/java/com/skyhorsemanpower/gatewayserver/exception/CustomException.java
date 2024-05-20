package com.skyhorsemanpower.gatewayserver.exception;

import lombok.Getter;

@Getter
public class CustomException extends RuntimeException {

    private final ResponseStatus responseStatus;

    public CustomException(ResponseStatus responseStatus) {
        super(responseStatus.getMessage());
        this.responseStatus = responseStatus;
    }

}
