package me.springInAction.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
//@Secured("{ROLE_USER,ROLE_ADMIN}")
//@PreAuthorize("hasAnyRole('USER' , 'ADMIN')")
public class MyController {

    @GetMapping("/home")
    public String home(){
        return "home";
    }

    @GetMapping("/product")
    public String product(){
        return "product";
    }

    @RequestMapping("/login")
    public String login(){
        return "login";
    }

    @GetMapping("/403")
    public String accessDenied(){
        return "403";
    }
}
