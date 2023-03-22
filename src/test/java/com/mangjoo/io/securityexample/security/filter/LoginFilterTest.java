package com.mangjoo.io.securityexample.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginFilterTest {

    LoginFilter loginFilter = new LoginFilter("/login", new ObjectMapper(), null, null);

    @Test
    @DisplayName("json 아닐 때 예외 발생 테스트")
    void loginFilterTest_exception() {
        //given

        //when
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setAttribute("username", "na");
        request.setAttribute("password", "na");
        request.setContentType("application/xml");
        MockHttpServletResponse response = new MockHttpServletResponse();

        //then
        assertThatThrownBy(() -> loginFilter.attemptAuthentication(request, response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Content type must be application/json");
    }

    @Test
    @DisplayName("method가 post가 아닐 때 예외 발생 테스트")
    void not_post_exception() {
        //when
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        request.setAttribute("username", "na");
        request.setAttribute("password", "na");
        request.setContentType("application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();

        //then
        assertThatThrownBy(() -> loginFilter.attemptAuthentication(request, response))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("정상적인 로그인 테스트")
    void loginFilterTest() throws IOException {

        //when
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setContentType("application/json");
        request.setCharacterEncoding("UTF-8");
        String body = new ObjectMapper().writeValueAsString(new LoginRequest("na", "na"));
        request.setContent(body.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        //then
        Authentication authentication = loginFilter.attemptAuthentication(request, response);
        assertThat(authentication.getPrincipal()).isEqualTo("na");
    }

    @Test
    @DisplayName("json 프로퍼티가 LoginRequest와 일치하지 않을때 실패해야한다.")
    void not_same_property_name_exception() throws IOException {
        //given
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();

        //when
        request.setContentType("application/json");
        request.setCharacterEncoding("UTF-8");
        String jsonBody = """
                {
                    "user" : "user123",
                    "password" : "1234"
                }
                """.trim();
        request.setContent(jsonBody.getBytes());

        //then
        assertThatThrownBy(() -> loginFilter.attemptAuthentication(request, response))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("json parse error");
    }
}
