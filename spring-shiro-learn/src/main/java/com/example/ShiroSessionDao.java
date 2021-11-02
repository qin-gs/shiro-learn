package com.example;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.io.*;
import java.util.List;

/**
 * session的存储
 */
@Repository
public class ShiroSessionDao extends EnterpriseCacheSessionDAO {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    protected Serializable doCreate(Session session) {
        Serializable sessionId = generateSessionId(session);
        assignSessionId(session, sessionId);
        String sql = "insert into session(id, session) values (?, ?)";
        jdbcTemplate.update(sql, sessionId, serialize(session));
        return sessionId;
    }

    @Override
    protected Session doReadSession(Serializable sessionId) {
        String sql = "select id, session from session where id = ?";
        List<String> sessions = jdbcTemplate.queryForList(sql, String.class, sessionId);
        return deserialize(sessions.get(0));
    }

    private String serialize(Session session) {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(stream);
            oos.writeObject(session);
            return Base64.decodeToString(stream.toByteArray());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    private Session deserialize(String str) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(str)));
            return ((Session) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }
}
