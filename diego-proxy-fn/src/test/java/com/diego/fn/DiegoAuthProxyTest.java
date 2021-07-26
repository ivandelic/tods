package com.diego.fn;

import com.fnproject.fn.testing.*;
import org.junit.*;

import static org.junit.Assert.*;

public class DiegoAuthProxyTest {

    @Rule
    public final FnTestingRule testing = FnTestingRule.createDefault();

    public void shouldReturnGreeting() {
        testing.givenEvent().enqueue();
        testing.thenRun(DiegoAuthProxy.class, "handleRequest");

        FnResult result = testing.getOnlyResult();
        assertEquals("Hello, world!", result.getBodyAsString());
    }

}