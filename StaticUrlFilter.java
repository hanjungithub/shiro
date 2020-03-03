package com.hzdaba.config.shiro;

import com.hzdaba.dic.Constants;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 自定义静态URL过滤器，防止页面静态资源缓存
 * Created by DELL on 2018/03/16.
 */
public class StaticUrlFilter implements Filter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String requestURL = req.getRequestURL().toString();
        String queryStr = req.getQueryString();

        // add timestamp to static resource, to avoid cache
        if(requestURL != null) {// && (requestURL.endsWith(".js") || requestURL.endsWith(".css"))
            String newURL = null;
            if (StringUtils.isNotBlank(queryStr) && queryStr.trim().indexOf(Constants.STATIC_TAIL) == -1) {
                newURL = requestURL + "?" + queryStr + "&" + Constants.STATIC_TAIL + new Date().getTime();
                resp.sendRedirect(newURL);
                return;
            }
            if (StringUtils.isBlank(queryStr)) {
                newURL = requestURL + "?" + Constants.STATIC_TAIL + new Date().getTime();
                resp.sendRedirect(newURL);
                return;
            }

            try {
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                logger.error(e.toString());
            }
            return;
        }
    }

    @Override
    public void destroy() {

    }
}
