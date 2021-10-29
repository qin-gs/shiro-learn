package com.example.session;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListenerAdapter;

public class MySessionListener extends SessionListenerAdapter {

    @Override
    public void onStart(Session session) {
        super.onStart(session);
    }
}
