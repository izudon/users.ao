package com.incrage.ao.users;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class DefaultController {

    @RequestMapping("/**")
    public Map<String, Object> handleAll() {
        return Collections.emptyMap(); // => {}
    }
}
