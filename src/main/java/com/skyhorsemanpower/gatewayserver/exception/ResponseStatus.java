package com.skyhorsemanpower.gatewayserver.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ResponseStatus {
    /**
     * 200: 요청 성공
     **/
    SUCCESS(200, "요청에 성공했습니다."),

    /**
     * 토큰 에러
     */
    INVALID_SIGNATURE_TOKEN(401, "시그니처 검증에 실패한 토큰입니다."),
    DAMAGED_TOKEN(401, "손상된 토큰입니다."),
    UNSUPPORTED_TOKEN(401, "지원하지 않는 토큰입니다."),
    EXPIRED_TOKEN(401, "만료된 토큰입니다."),
    INVALID_TOKEN(401, "잘못된 토큰입니다."),
    JWT_FAIL_WITH_REFRESH(401, "Refresh 토큰은 사용할 수 없습니다."),
    VERIFICATION_FAILED(401, "검증에 실패한 토큰입니다."),
    NOT_FOUND_TOKEN(401, "토큰이 없습니다.");

    private final int code;
    private final String message;
}
