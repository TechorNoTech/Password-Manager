import bodyParser from "body-parser";
import express from "express";
import {dirname} from "path";
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
// app.use(express.static("public"));
app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({extended: true}));

app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.post("/submit", (req, res) =>{
    const combi = req.body["email"] + req.body["password"];
    res.render("index.ejs", {combiC: combi });

});

app.get("/about", (req, res)=> {
    res.render("about.ejs");
});

app.get("/contact", (req, res)=> {
    res.render("contact.ejs");
});

app.get("/dashboard", (req, res)=> {
    res.render("dashboard.ejs");
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});