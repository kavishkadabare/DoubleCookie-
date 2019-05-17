<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
<style>body {font-family: Arial, Helvetica, sans-serif;}
form {border: 3px solid #f1f1f1;}

input[type=text], input[type=password] {
  width: 100%;
  padding: 12px 20px;
  margin: 8px 0;
  display: inline-block;
  border: 1px solid #ccc;
  box-sizing: border-box;
}

button {
  background-color: #4CAF50;
  color: white;
  padding: 14px 20px;
  margin: 8px 0;
  border: none;
  cursor: pointer;
  width: 100%;
}

button:hover {
  opacity: 0.8;
}
</style>
</head>
<body>

<div align= "center" style="width:100%">
<div align="center" style="width:40%">
<H1>Home </H1>
<%= request.getAttribute("csrfToken") %>
<form action="WelcomeServlet" method="POST">
<input name="token" type ="hidden" value=<%= request.getAttribute("csrfToken") %>/>
<h4>Type something</h4><input type = "text"/>
<button type = "submit">Submit </button>
</form>
</div>
</div>
</body>
</html>