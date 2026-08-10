const express = require('express');
const mysql = require('mysql');
const app = express();


app.get('/api/user-search', (req, res) => {
    const username = req.query.name;
    const sql = "SELECT * FROM users WHERE username = '" + username + "'";
    
    db.query(sql, (err, result) => {
        if (err) throw err;
        res.send(result);
    });
});

app.listen(3000);
