

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.swing.JOptionPane;

/**
 * Servlet implementation class WelcomeServlet
 */
@WebServlet("/WelcomeServlet")
public class WelcomeServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public WelcomeServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
		
		 //HttpSession session = request.getSession();
		
		Cookie[] cookies = request.getCookies();
		
		String cookieValue = null;
		System.out.println("Cookie List");
		for(Cookie cookie : cookies){
		    
				System.out.println(cookie.getName()+"  "+cookie.getValue());
			if("test_cookie".equals(cookie.getName())){
		    	cookieValue = cookie.getValue();
		    }
		}

	        //String storedToken = "Hi";//CSRFToken.getToken(session.getId());
	        String token = request.getParameter("token");
	       
	        System.out.println("Dead duck");
	        System.out.println(cookieValue+"   "+token);
	        
	        token = token.replace("/","");
	        if (cookieValue.equals(token)) {
	               System.out.println("You are a valid User");
	               JOptionPane.showMessageDialog(null, "Valid Request!!!");
	               //Continue with Application
	               }
	        else {
	        	System.out.println("You are not a valid User!! WARNING!!! WARNING!!!");
	        	JOptionPane.showMessageDialog(null, "Invalid Request");	        	
	        }
	}

}
