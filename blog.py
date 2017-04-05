#
# blog.py -- implementation of a multi-user blog.
#
import os
import jinja2
import webapp2
import re
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Global constants
SECRET = 'TheQuickBrownFox'
USER_ERROR = "That's not a valid username."
EXISTS_ERROR = "That user already exists."
PWD_ERROR = "This wasn't a valid password."
PWD_MISMATCH = "Your passwords didn't match."
EMAIL_ERROR = "That's not a valid email."
LOGIN_ERROR = "Invalid login."

# Global variables
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
COOKIE_RE = re.compile(r'.+=;\s*Path=/')


class ErrorNumbers:
    ''' This class enumerates the types of user errors.
    '''
    CANT_EDIT_POST = 0
    CANT_DELETE_POST = 1
    CANT_LIKE_OWN_POST = 2
    CANT_LIKE_SAME_POST = 3
    CANT_DISLIKE_OWN_POST = 4
    CANT_DISLIKE_SAME_POST = 5
    CANT_COMMENT_OWN_POST = 6
    CANT_EDIT_COMMENT = 7
    CANT_DELETE_COMMENT = 8


class Account(db.Model):
    ''' This class is a Datastore model of a user.

        Attributes:
            username: A unique user name.
            pwd_hash: A hash of the username + password + salt.
            email:    User's email address.
    '''

    username = db.StringProperty(required=True)
    pwd_hash = db.StringProperty(required=True)
    email = db.StringProperty()


class Likes(db.Model):
    ''' This class is a Datastore model of a like.

        Attributes:
            liker:   User name of the user who submitted the like.
            post_id: Unique ID number of the post that has been liked.
    '''
    liker = db.ReferenceProperty(Account,
                                 collection_name='likes',
                                 required=True)
    post_id = db.IntegerProperty(required=True)


class Dislikes(db.Model):
    ''' This class is a Datastore model of a dislike.

        Attributes:
            disliker: User name of the user who submitted the dislike.
            post_id:  Unique ID number of the post that has been disliked.
    '''
    disliker = db.ReferenceProperty(Account,
                                    collection_name='dislikes',
                                    required=True)
    post_id = db.IntegerProperty(required=True)


class Comment(db.Model):
    ''' This class is a Datastore model of a comment.

        Attributes:
            commenter: User name of the user who submitted the comment.
            post_id:   Unique ID number of the post that has been commented on.
            comment:   Content of the comment.
            created:   Automatically generated DateTime when the comment was
                       submitted.
    '''
    commenter = db.ReferenceProperty(Account,
                                     collection_name='comments',
                                     required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class BlogEntry(db.Model):
    ''' This class is a Datastore model of a blog post.

        Attributes:
            subject:  Subject of the post.
            content:  Content of the post.
            created:  Automatically generated DateTime when the post was
                      submitted.
            author:   User name of the author of the post.
    '''
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.ReferenceProperty(Account,
                                  collection_name='posts',
                                  required=True)
    likes = db.IntegerProperty(required=True)
    dislikes = db.IntegerProperty(required=True)


class Handler(webapp2.RequestHandler):
    ''' This class is a webapp2 Request Handler class. It inherits from
        webapp2.RequestHandler class and serves as the base class for all of
        the Handler classes of this application. It contains methods for
        rendering web pages using the jinja2 templating library, as well as
        processing user passwords.
    '''
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def valid_username(self, username):
        return USER_RE.match(username)

    def valid_password(self, password):
        return PWD_RE.match(password)

    def valid_email(self, email):
        if not email:
            valid = True
        else:
            valid = EMAIL_RE.match(email)

        return valid

    def hash_str(self, s):
        return hmac.new(SECRET, s).hexdigest()

    def make_secure_val(self, s):
        hash = self.hash_str(s)
        return "%s|%s" % (s, hash)

    def check_secure_val(self, h):
        val = h.split('|')[0]
        if h == self.make_secure_val(val):
            return val
        else:
            return None

    def make_salt(self):
        return ''.join(random.choice(string.letters) for i in range(0, 5))

    def make_pw_hash(self, name, pw, salt=None):
        if not salt:
            salt = self.make_salt()

        h = hashlib.sha256(name+pw+salt).hexdigest()

        return "%s,%s" % (h, salt)

    def valid_pw(self, name, pw, h):
        salt = h.split(',')[1]
        return h == self.make_pw_hash(name, pw, salt)

    def ValidateUser(self):
        user_id_str = self.request.cookies.get("user_id")

        # Verify the user_id hash
        if user_id_str:
            cookie_val = self.check_secure_val(user_id_str)

            if cookie_val:
                ID = int(cookie_val)

                # Lookup the name of the user_id
                user = Account.get_by_id(int(ID), parent=None)

                return True, user
        return False, None

    def RegisterUser(self, name, pwd, eml):
        # make pw hash and store in db
        h = self.make_pw_hash(name, pwd)

        a = Account(username=name, pwd_hash=h, email=eml)
        a.put()

        self.SetUserCookie(a)

    def SetUserCookie(self, a):
        ID = a.key().id()
        cookie_val = self.make_secure_val(str(ID))

        # Set-Cookie with user_id=id|hash
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s; Path=/' % cookie_val)

    def ValidatePassword(self, name, pwd, pwd_hash):
        return self.valid_pw(name, pwd, pwd_hash)

    def GetPostById(self, ID):
        if ID:
            post = BlogEntry.get_by_id(int(ID), parent=None)

            # get_by_id() will return None if no post exists.
            return post
        else:
            return None

    def UserOwnsPost(self, user, post):
        if post:
            if post.author.username == user.username:
                return True
        return False
        
    def UserDoesntOwnPost(self, user, post):
        if post:
            if post.author.username != user.username:
                return True
        return False

    def GetCommentById(self, ID):
        if ID:
            comment = Comment.get_by_id(int(ID), parent=None)

            # get_by_id() will return None if no comment exists.
            return comment
        else:
            return None

    def UserOwnsComment(self, user, comment):
        if comment:
            if comment.commenter.username == user.username:
                return True
        return False


class WelcomeHandler(Handler):
    ''' This class handles the request for the Welcome page. It inherits from
        the Handler class.
    '''
    def get(self):
        loggedIn, user = self.ValidateUser()
        if user:
            self.render("welcome.html", userName=user.username)
        else:
            self.redirect("/signup")


class SignupHandler(Handler):
    ''' This class handles the request for the Signup page. It inherits from
        the Handler class.
    '''
    def get(self):
        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("signup.html",
                    user_value="",
                    user_error="",
                    pwd_error="",
                    pwd_mismatch="",
                    email_value="",
                    email_error="",
                    loggedIn=loggedIn,
                    userName=name)

    def post(self):
        exists = False
        name = self.request.get("username")
        pwd = self.request.get("password")
        ver = self.request.get("verify")
        eml = self.request.get("email")
        count = 0

        if (self.valid_username(name) and
                self.valid_password(pwd) and
                pwd == ver and
                self.valid_email(eml)):

            # Check if user is already in db
            query = "select * from Account where username='%s' limit 1" % name
            q = db.GqlQuery(query)
            count = q.count()

            if count == 0:
                # Make a password hash and store it in a new Datastore entry.
                self.RegisterUser(name, pwd, eml)

                # Redirection - pass username
                redAddress = "/welcome"
                self.redirect(redAddress)

                return

        # An error was found in the signup data.
        user_error = ""
        pwd_error = ""
        pwd_mismatch = ""
        email_error = ""

        if not self.valid_username(name):
            user_error = USER_ERROR
        elif count > 0:
            user_error = EXISTS_ERROR

        if not self.valid_password(pwd):
            pwd_error = PWD_ERROR
        if not pwd == ver:
            pwd_mismatch = PWD_MISMATCH
        if not self.valid_email(eml):
            email_error = EMAIL_ERROR

        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("signup.html",
                    user_value=name,
                    user_error=user_error,
                    pwd_error=pwd_error,
                    pwd_mismatch=pwd_mismatch,
                    email_value=eml,
                    email_error=email_error,
                    userName=name,
                    loggedIn=loggedIn)


class LoginHandler(Handler):
    ''' This class handles the request for the Login page. It inherits from
        the Handler class.
    '''
    def get(self):
        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("login.html",
                    login_error="",
                    userName=name,
                    loggedIn=loggedIn)

    def post(self):
        name = self.request.get("username")
        pwd = self.request.get("password")

        # Check if user exists in db
        query = "select * from Account where username='%s' limit 1" % name
        q = db.GqlQuery(query)
        count = q.count()

        if count == 0:
            # Re-render form with error message
            loggedIn, user = self.ValidateUser()

            if user:
                name = user.username
            else:
                name = ""

            self.render("login.html",
                        login_error=LOGIN_ERROR,
                        userName=name,
                        loggedIn=loggedIn)
        else:
            # Validate password
            User = q.get()
            pwd_hash = User.pwd_hash
            if self.ValidatePassword(name, pwd, pwd_hash):
                # Get the user ID and make a login hash
                self.SetUserCookie(User)

                # Redirection - pass username
                self.redirect("/")
            else:
                # Re-render form with error message
                loggedIn, user = self.ValidateUser()

                if user:
                    name = user.username
                else:
                    name = ""

                self.render("login.html",
                            login_error=LOGIN_ERROR,
                            userName=name,
                            loggedIn=loggedIn)

        return


class LogoutHandler(Handler):
    ''' This class handles the request for the Logout page. It inherits from
        the Handler class.
    '''
    def get(self):
        # Set cookie to empty
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

        # Redirect to signup
        self.redirect("/")


class DeletePostHandler(Handler):
    ''' This class handles the request to delete a post. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            post = BlogEntry.get_by_id(int(ID), parent=None)

            if ID and post:
                #if post in user.posts:
                if post.author.username == user.username:
                    # Delete entry
                    post.delete()
                    self.redirect("/")

                else:
                    ErrNo = str(ErrorNumbers.CANT_DELETE_POST)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")


class PostHandler(Handler):
    ''' This class is a base class for handling post editing requests. It
        inherits from the Handler class, and is the base class for the
        NewPostHandler and EditPostHandler classes.
    '''
    def render_form(self, subject="", content="", error=""):
        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("edit_post.html",
                    subject=subject,
                    content=content,
                    error=error,
                    userName=name,
                    loggedIn=loggedIn)


class NewPostHandler(PostHandler):
    ''' This class handles the request for the New Post page. It inherits from
        the Handler class.
    '''
    def get(self):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            self.render_form()
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        loggedIn, user = self.ValidateUser()
        if loggedIn:
            if (subject and content):
                be = BlogEntry(subject=subject,
                               content=content,
                               author=user,
                               likes=0,
                               dislikes=0)
                be.put()
                ID = be.key().id()

                redAddress = "/%s" % ID
                self.redirect(redAddress)

            else:
                error = "subject and content, please!"
                self.render_form(subject, content, error)


class EditPostHandler(PostHandler):
    ''' This class handles the request for the Edit Post page. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            post = self.GetPostById(ID)

            if post:
                if self.UserOwnsPost(user, post):
                    self.render_form(subject=post.subject, content=post.content)
                else:
                    redAddress = "/error/%s" % str(ErrorNumbers.CANT_EDIT_POST)
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")


    def post(self, ID):
        subject = self.request.get("subject")
        content = self.request.get("content")

        loggedIn, user = self.ValidateUser()
        if loggedIn:
            post = self.GetPostById(ID)
            if post:
                if self.UserOwnsPost(user, post):
                    if (subject and content):
                        post.subject = subject
                        post.content = content
                        post.put()

                        redAddress = "/%s" % ID
                        self.redirect(redAddress)
                    else:
                        error = "subject and content, please!"
                        self.render_form(subject, content, error)
                else:
                    # The user doesn't own this post.
                    self.redirect("/login")
            else:
                self.error(404)
        else:
            self.redirect("/login")


class LikeHandler(Handler):
    ''' This class handles the request to like a post. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            post = self.GetPostById(ID)
            if post:
                if self.UserDoesntOwnPost(user, post):
                    # Check if this user has already liked this post.
                    query = """select * from Likes
                                   where liker= :1 and post_id= :2
                                   limit 1"""
                    q = db.GqlQuery(query, user, int(ID))
                    count = q.count()

                    if count == 0:
                        # Increment the like count and put to Model.
                        post.likes = post.likes + 1
                        post.put()

                        # Add to Likes datastore.
                        likeEntry = Likes(liker=user,
                                          post_id=int(ID))
                        likeEntry.put()

                        # Redirect to blog.
                        self.redirect("/")
                    else:
                        ErrNo = str(ErrorNumbers.CANT_LIKE_SAME_POST)
                        redAddress = "/error/%s" % ErrNo
                        self.redirect(redAddress)
                else:
                    ErrNo = str(ErrorNumbers.CANT_LIKE_OWN_POST)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")


class DislikeHandler(Handler):
    ''' This class handles the request to dislike a post. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            post = self.GetPostById(ID)
            if post:
                if self.UserDoesntOwnPost(user, post):
                    # Check if this user has already disliked this post.
                    query = """select * from Dislikes
                                   where disliker= :1 and post_id= :2
                                   limit 1"""
                    q = db.GqlQuery(query, user, int(ID))
                    count = q.count()

                    if count == 0:
                        # Increment the dislike count and put to datastore.
                        post.dislikes = post.dislikes + 1
                        post.put()

                        # Add to Likes datastore.
                        dislikeEntry = Dislikes(disliker=user,
                                                post_id=int(ID))
                        dislikeEntry.put()

                        # Redirect to blog.
                        self.redirect("/")
                    else:
                        ErrNo = str(ErrorNumbers.CANT_DISLIKE_SAME_POST)
                        redAddress = "/error/%s" % ErrNo
                        self.redirect(redAddress)
                else:
                    ErrNo = str(ErrorNumbers.CANT_DISLIKE_OWN_POST)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")


class NewCommentHandler(Handler):
    ''' This class handles the request to add a comment on a post. It inherits
        from the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            post = self.GetPostById(ID)

            if post:
                if self.UserDoesntOwnPost(user, post):
                    # Find if user has already left a comment for this post.


                    self.render("edit_comment.html",
                                subject=post.subject,
                                comment="",
                                loggedIn=loggedIn,
                                userName=user.username)
                else:
                    ErrNo = str(ErrorNumbers.CANT_COMMENT_OWN_POST)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")

    def post(self, ID):
        user_comment = self.request.get("comment")

        loggedIn, user = self.ValidateUser()
        if loggedIn:
            post = self.GetPostById(ID)
            if post:
                if self.UserDoesntOwnPost(user, post):
                    if user_comment:
                        c = Comment(commenter=user,
                                    post_id=int(ID),
                                    comment=user_comment)
                        c.put()

                        redAddress = "/%s" % ID
                        self.redirect(redAddress)

                    else:
                        self.redirect("/")
                else:
                    ErrNo = str(ErrorNumbers.CANT_COMMENT_OWN_POST)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)

            else:
                self.error(404)
        else:
            self.redirect("/login")


class EditCommentHandler(Handler):
    ''' This class handles the request to add a comment on a post. It inherits
        from the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            comment = self.GetCommentById(ID)

            if comment:
                post = self.GetPostById(comment.post_id)
                if post:
                    if self.UserOwnsComment(user, comment):
                        self.render("edit_comment.html",
                                    subject=post.subject,
                                    comment=comment.comment,
                                    loggedIn=loggedIn,
                                    userName=user.username)
                    else:
                        ErrNo = str(ErrorNumbers.CANT_EDIT_COMMENT)
                        redAddress = "/error/%s" % ErrNo
                        self.redirect(redAddress)
                else:
                    self.error(404)
            else:
                self.error(404)
        else:
            self.redirect("/login")

    def post(self, ID):
        user_comment = self.request.get("comment")

        loggedIn, user = self.ValidateUser()
        if loggedIn:
            comment = self.GetCommentById(ID)
            if comment:
                if self.UserOwnsComment(user, comment):
                    if user_comment:
                        comment.comment = user_comment
                        comment.put()

                        redAddress = "/%s" % comment.post_id
                        self.redirect(redAddress)

                    else:
                        self.redirect("/")
                else:
                    ErrNo = str(ErrorNumbers.CANT_EDIT_COMMENT)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)

            else:
                self.error(404)
        else:
            self.redirect("/login")


class DeleteCommentHandler(Handler):
    ''' This class handles the request to delete a comment. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        loggedIn, user = self.ValidateUser()

        if loggedIn:
            comment = Comment.get_by_id(int(ID), parent=None)

            if ID and comment:
                if comment.commenter.username == user.username:
                    # Delete entry
                    comment.delete()

                    redAddress = "/%s" % comment.post_id
                    self.redirect(redAddress)                        

                else:
                    ErrNo = str(ErrorNumbers.CANT_DELETE_COMMENT)
                    redAddress = "/error/%s" % ErrNo
                    self.redirect(redAddress)
            else:
                self.error(404)
        else:
            self.redirect("/login")


class ErrorHandler(Handler):
    ''' This class handles requests for the error page. It inherits from
        the Handler class.
    '''
    def get(self, ErrNo):
        Error = int(ErrNo)
        if Error == ErrorNumbers.CANT_DELETE_POST:
            errorMessage = "Only author of post can delete it."
        elif Error == ErrorNumbers.CANT_EDIT_POST:
            errorMessage = "Only author of post can edit it."
        elif Error == ErrorNumbers.CANT_LIKE_OWN_POST:
            errorMessage = "Author of a post can't like it."
        elif Error == ErrorNumbers.CANT_LIKE_SAME_POST:
            errorMessage = "You have already liked this post."
        elif Error == ErrorNumbers.CANT_DISLIKE_OWN_POST:
            errorMessage = "Author of a post can't dislike it."
        elif Error == ErrorNumbers.CANT_DISLIKE_SAME_POST:
            errorMessage = "You have already disliked this post."
        elif Error == ErrorNumbers.CANT_COMMENT_OWN_POST:
            errorMessage = "Can't comment on your own post."
        elif Error == ErrorNumbers.CANT_EDIT_COMMENT:
            errorMessage = "Can't edit other user's comments."
        elif Error == ErrorNumbers.CANT_DELETE_COMMENT:
            errorMessage = "Can't delete other user's comments."
        else:
            errorMessage = ""

        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("error.html",
                    userName=user.username,
                    loggedIn=loggedIn,
                    error=errorMessage)


class BlogEntryHandler(Handler):
    ''' This class handles the request for a blog post page. It inherits from
        the Handler class.
    '''
    def get(self, ID):
        postList = []
        post = self.GetPostById(ID)

        if post:
            postList.append(post)
            loggedIn, user = self.ValidateUser()

            # Get comments for the blog entry.
            query = """select * from Comment
                            where post_id = :1
                            order by created DESC limit 50"""
                
            user_comments = db.GqlQuery(query, int(ID))

            if user:
                name = user.username
            else:
                name = ""

            self.render("blog_entry.html",
                        userName=name,
                        loggedIn=loggedIn,
                        entries=postList,
                        comments=user_comments)

            return

        self.error(404)


class BlogHandler(Handler):
    ''' This class handles the request for the blog home page. It inherits from
        the Handler class.
    '''
    def get(self):
        query = "select * from BlogEntry order by created DESC limit 10"
        entries = db.GqlQuery(query)

        loggedIn, user = self.ValidateUser()

        if user:
            name = user.username
        else:
            name = ""

        self.render("blog.html",
                    userName=name,
                    loggedIn=loggedIn,
                    entries=entries)


app = webapp2.WSGIApplication([('/', BlogHandler),
                               ('/newpost', NewPostHandler),
                               ('/editpost/(\d*)', EditPostHandler),
                               ('/delete/(\d*)', DeletePostHandler),
                               ('/(\d+)', BlogEntryHandler),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/welcome', WelcomeHandler),
                               ('/like/(\d*)', LikeHandler),
                               ('/dislike/(\d*)', DislikeHandler),
                               ('/error/(\d*)', ErrorHandler),
                               ('/newcomment/(\d*)', NewCommentHandler),
                               ('/editcomment/(\d*)', EditCommentHandler),
                               ('/deletecomment/(\d*)', DeleteCommentHandler)],
                              debug=True)
