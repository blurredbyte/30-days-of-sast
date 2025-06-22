class UsersController < ApplicationController
  def show
    # This is a simplified example. In a real app, @name might come from a database
    # based on params[:id], but here we'll take it directly from params for clarity.
    user_provided_name = params[:name]

    # VULNERABILITY: Using html_safe on unescaped user input
    # Rails normally auto-escapes content in ERB templates.
    # Calling .html_safe tells Rails that the string is safe to render as HTML,
    # bypassing the default XSS protection. If 'user_provided_name' contains
    # malicious script tags, they will be executed in the browser.
    @name_html_safe = user_provided_name.html_safe if user_provided_name.present?

    @name_default_escaped = user_provided_name # This would be escaped by default in ERB

    # A SAST tool should flag the use of .html_safe on 'params[:name]'
    # or data derived directly from it without prior sanitization.

    # Example route to trigger this in config/routes.rb:
    # get 'users/show', to: 'users#show'
    # Vulnerable URL: /users/show?name=<script>alert('XSS')</script>
  end
end
