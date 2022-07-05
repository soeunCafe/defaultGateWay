//공통 필터

package com.example.gateway.filter;


import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Component
@Slf4j
public class GlobalFilter extends AbstractGatewayFilterFactory<GlobalFilter.Config> {

    public GlobalFilter(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config){

        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();
            log.info(".........."+config.baseMessage);
            if (config.preLogger){
                log.info("global filter prelogger");
            }

            log.info(request.getId()+" "+
                    request.getMethod()+" "+
                    request.getPath()+" "+
                    request.getBody());

            return chain.filter(exchange).then(Mono.fromRunnable(()->{
                if (config.postLogger) {
//                    log.info(String.valueOf(response.getStatusCode()));
                    log.info(String.valueOf(response.getStatusCode())+" "+
                            response.toString());
                }
            }));
        });
    }

    @Data
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}