package com.secure.notes;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @GetMapping("/hello")
    public String sayHello(){
        return "hello from the HelloController";
    }

    @GetMapping("/contact")
    public String sayContact(){
        return "hello from the Contact Controller";
    }
}
