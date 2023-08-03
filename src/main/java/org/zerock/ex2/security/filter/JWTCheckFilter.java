package org.zerock.ex2.security.filter;

import com.google.gson.Gson;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.ex2.dto.MemberDTO;
import org.zerock.ex2.util.JWTUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {

    // 어떤 요청이 들어왔는데 true면 필터링을 하지 않음
    // api/member는 필터X
    // api/todo는 필터 O
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        //Preflight
        // 프리플라이트는 필터 X . 프리플라이트는 OPTIONS로 날라가기 떄문에 OPTIONS와 같으면 true
        if(request.getMethod().equals("OPTIONS")){
            return true;
        }

        // /api/todo/list /api/member/login
        String path = request.getRequestURI();

        // 이거는 필터링 하지마! true를 줘서 필터링 하지않게끔 설정
        // if(path.equals("/api/member/login") || path.equals("/api/member/refresh")){
        // 같은 코드! -> /api/member로 시작하는 경로는 필터하지마~!라는 내용
        if (path.startsWith("/api/member/")){
            return true;
        }

        // login으로 시작하면 필터X
        if(path.startsWith("/login")){
            return true;
        }

        // oauth2로 시작하면 필터X
        if(path.startsWith("/oauth2")){
            return true;
        }

        if(path.endsWith(".ico")){
            return true;
        }

        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("------------doFilterInternal----------------");

        log.info("------------doFilterInternal----------------");


        String authHeaderStr = request.getHeader("Authorization");

        try {
            //Bearer accestoken...
            String accessToken = authHeaderStr.substring(7);
            Map<String, Object> claims = JWTUtil.validateToken(accessToken);

            log.info("JWT claims: " + claims);

            String email = (String) claims.get("email");
            String pw = (String) claims.get("pw");
            String nickname = (String) claims.get("nickname");
            Boolean social = (Boolean) claims.get("social");
            List<String> roleNames = (List<String>) claims.get("roleNames");

            // JWT를 가지고 memberDTO 객체 생성 ( 사용자 정보 , 시큐리티 정보 )
            MemberDTO memberDTO = new MemberDTO(email, pw, nickname, social.booleanValue(), roleNames);

            log.info("-----------------------------------");
            log.info(memberDTO);
            log.info(memberDTO.getAuthorities());

            // MerberDTO를 시큐리티 안에다 포함시키는 코드
            // JWT를 가지고 예전에 사용했던 시큐리티 처럼 사용가능하게끔 설정해주는 것이다.
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(memberDTO, pw, memberDTO.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            // 문제가 없다면 통과
            filterChain.doFilter(request, response);

        }catch(Exception e) {

            log.error("JWT Check Error..............");
            log.error(e.getMessage());

            Gson gson = new Gson();
            String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));

            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();
            printWriter.println(msg);
            printWriter.close();
        }
    }
}