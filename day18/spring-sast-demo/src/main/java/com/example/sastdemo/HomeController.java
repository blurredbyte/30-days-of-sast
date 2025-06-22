package com.example.sastdemo;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {

    @GetMapping("/greeting")
    public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        // Directly using user input with th:utext in the template can lead to XSS
        // For a safer alternative, use th:text which escapes HTML.
        // Example: <p th:text="'Hello, ' + ${name} + '!'"></p>
        return "greeting"; // Renders greeting.html
    }

    @GetMapping("/unsafe-greeting")
    public String unsafeGreeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        // This will be used with th:utext to demonstrate XSS
        return "unsafe_greeting";
    }
}
