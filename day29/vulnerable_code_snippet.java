// Assume these classes and interfaces exist elsewhere for context:
// package com.example.app;

// interface User {
//     Long getId();
//     String getUsername();
// }

// interface Invoice {
//     Long getId();
//     Long getUserId(); // ID of the user who owns this invoice
//     String getDetails();
//     java.math.BigDecimal getAmount();
// }

// interface InvoiceService {
//     Invoice getInvoiceById(long invoiceId);
// }

// interface HttpServletRequest {
//     String getParameter(String name);
//     HttpSession getSession();
// }

// interface HttpServletResponse {
//     void sendError(int sc, String msg) throws java.io.IOException;
//     java.io.PrintWriter getWriter() throws java.io.IOException;
//     int SC_FORBIDDEN = 403;
//     int SC_NOT_FOUND = 404;
//     int SC_INTERNAL_SERVER_ERROR = 500;
// }

// interface HttpSession {
//     Object getAttribute(String name);
// }


// Simplified Servlet/Controller Snippet
// public class InvoiceServlet extends SomeBaseServlet { // Fictional base class

    // protected void doGet(HttpServletRequest request, HttpServletResponse response)
    //         throws ServletException, java.io.IOException {

        // Assume InvoiceService and User are properly initialized/obtained
        // InvoiceService invoiceService = ... ; // Injected or retrieved
        // User currentUser = (User) request.getSession().getAttribute("currentUser");

        // if (currentUser == null) {
        //     response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not authenticated.");
        //     return;
        // }

        String invoiceIdParam = request.getParameter("id"); // SOURCE: User-controlled input

        if (invoiceIdParam == null || invoiceIdParam.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invoice ID is required.");
            return;
        }

        try {
            long invoiceId = Long.parseLong(invoiceIdParam);

            // SINK: User input directly used to fetch a sensitive object (Invoice)
            Invoice invoice = invoiceService.getInvoiceById(invoiceId);

            if (invoice != null) {
                // VULNERABILITY: Missing Authorization Check!
                // The code does not verify if the 'currentUser' is authorized to view this specific 'invoice'.
                // Any authenticated user can view any invoice by changing the 'id' parameter.

                // This is an Insecure Direct Object Reference (IDOR).
                response.getWriter().write("Invoice Details: " + invoice.getDetails());
                // In a real app, this would render a full page or JSON response.

            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Invoice not found.");
            }

        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Invoice ID format.");
        } catch (Exception e) {
            // Log error
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred.");
        }
    // }
// }

/*
Relevant context for the snippet (to make it somewhat runnable for SAST if needed, but keep it simple):
This snippet would typically be within a method of a class handling HTTP requests.
For example:
*/
// --- Start of context for SAST tool parsing ---
package com.example.app;

// Dummy interfaces/classes for SAST tool to parse
interface User { Long getId(); }
interface Invoice { Long getId(); Long getUserId(); String getDetails(); }
interface InvoiceService { Invoice getInvoiceById(long invoiceId); }
interface HttpServletRequest { String getParameter(String name); HttpSession getSession(); }
interface HttpServletResponse { void sendError(int sc, String msg) throws java.io.IOException; java.io.PrintWriter getWriter() throws java.io.IOException; int SC_FORBIDDEN = 403; int SC_NOT_FOUND = 404; int SC_BAD_REQUEST = 400; int SC_INTERNAL_SERVER_ERROR = 500; int SC_UNAUTHORIZED = 401;}
interface HttpSession { Object getAttribute(String name); }
class ServletException extends Exception {}


public class InvoiceServletController {
    private InvoiceService invoiceService; // Assume this is injected

    public InvoiceServletController(InvoiceService service) {
        this.invoiceService = service;
    }

    protected void handleGetInvoice(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {

        User currentUser = (User) request.getSession().getAttribute("currentUser");

        if (currentUser == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not authenticated.");
            return;
        }

        String invoiceIdParam = request.getParameter("id"); // SOURCE

        if (invoiceIdParam == null || invoiceIdParam.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invoice ID is required.");
            return;
        }

        try {
            long invoiceId = Long.parseLong(invoiceIdParam);

            Invoice invoice = invoiceService.getInvoiceById(invoiceId); // SINK

            if (invoice != null) {
                // VULNERABILITY: No check here if currentUser.getId() matches invoice.getUserId()
                // This is the IDOR.
                response.getWriter().write("Invoice Details: " + invoice.getDetails());
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Invoice not found.");
            }

        } catch (NumberFormatException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Invoice ID format.");
        } catch (Exception e) {
            // In a real app, log e
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred.");
        }
    }
}
// --- End of context for SAST tool parsing ---
