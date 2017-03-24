###############################################################################
                   Multi-User Blog Web Application
###############################################################################

1. What Is It?
   -----------
   The Multi-User Blog Web Application is a Python application that implements
   a web-based multi-user blog. Users can post information to the blog and also
   comment on other user's posts. Users can register with a unique user name and
   password. The application is written to be hosted on the Google Cloud 
   Platform using the Google App Engine.
   This application was created as partial fulfillment of the Udacity Full
   Stack Web Developer Nanodegree. Specifically, it is Project 3: Multi-User
   Blog.

2. Installation
   ------------
   The source code for this application can be obtained from the following
   GitHub repository:
      https://github.com/MickElliott/fsnd-multi-user-blog

   The application consists of the following files:
      blog.py
      index.yaml
      readme.txt
      templates\base.html
      templates\blog.html
      templates\blog_entry.html
      templates\edit_comment.html
      templates\edit_post.html
      templates\error.html
      templates\login.html
      templates\signup.html
      templates\welcome.html
      static\main.css

3. Python Version
   --------------
   This application was developed using Python version 2.7.13

4. Usage
   -----
   1. The application is written to be run using the Google App Engine. The code
      can be obtained by cloning the GitHub repository with the following command:
        $ git clone https://github.com/MickElliott/fsnd-multi-user-blog.git

   2. To deploy the application to Google App Engine, the user must install the
      Google App Engine SDK. Instructions for that can be found at this URL:
        https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python

      The user must also sign up for a Google App Engine account and create a
      new project in the Google Developer Console. See the following URLs:
       https://console.cloud.google.com/appengine/
       https://console.cloud.google.com/

   3. The application can be deployed to the new project by using the following
      Google Cloud command:
       $ gcloud app deploy --project [YOUR_PROJECT_ID]

      Follow the App Engine Quickstart documentation to see how to get a sample
      application running.(https://cloud.google.com/appengine/docs/python/quickstart)

      Once deployed, the application can be found at:
           https://[YOUR_PROJECT_ID].appspot.com

      An example of the application can be found at the following URI:
           https://multi-user-blog-161422.appspot.com