import os
import logging

import webapp2
import jinja2

from google.appengine.ext import ndb
from account_func import *
from models import User, Post

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# set global jinja variable 'session' to an empty dict if it doesn't exist.
jinja_env.globals.setdefault('session', {})


def blog_key(name='default'):
    """An ancestor element key function for blogs within the Datastore. Various
        groups can be created for different names of blogs, 'default' by default.
    Args:
        name: The chosen group for the created blog post.
    """
    return ndb.Key('blogs', name)


def users_key(group='default'):
    """An ancestor element key function for users within the Datastore. Various
        groups can be created for different kinds of users, 'default' by default.
    Args:
        group: The chosen group for the created User.

    """
    return ndb.Key('users', group)


def fetch_username(user_id):
    """Returns a User entities username from a given user_id
    Args:
        user_id: the unique user_id corresponding to the given user in Datastore.
    Returns:
        The given user's username as a string if it exists, else returns NoneType object.
    """
    user = ndb.Key(User, int(user_id)).get()
    logging.info("The username of the user is: {0}".format(user.username))
    return user and user.username


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class BlogHandler(webapp2.RequestHandler):
    """ A Bloghandler class to carry out the methods required by our blog."""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    @staticmethod
    def render_str(template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, value):
        """Sets a secure cookie value using the make_secure_val function and GAE
            headers.add_header().
        Args:
            name: The name the cookie value is given.
            value: The value the cookie is to be given.
        """
        secure_val = make_secure_val(value)
        self.response.headers.add_header('Set-Cookie',
                                         '{0}={1}; Path=/'.format(name, secure_val))

    def get_verified_cookie(self, name):
        """Validates and returns a cookie value if it is legitimate
        Args:
            name: the name of the cookie that is to be read.
        Returns:
            The verified cookie value, as a string, without the hash value, provided the cookie 
            is valid and the cookie original value matches its hash value. 
        """
        cookie_val = self.request.cookies.get(name)
        # return using 'and' as a safeguard; only return the second val if the fist is true.
        return cookie_val and verify_secure_val(cookie_val)

    def logout(self):
        """Sets the secure Set-Cookie header to an empty user_id, so it is no longer
            associated with user.
        """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.set_session()

    def login(self, user_id_str):
        """Sets the secure Set-Cookie header to the associated user_id, so the user is
            recognised by the application.
        Args:
            user_id_str: The user id string of the user to be logged in.
        """
        self.set_cookie('user_id', user_id_str)

    def initialize(self, *args, **kwargs):
        """An initialize function that gets run during every request. The user_id is stored within 
             self.user after every request, to prevent repetitive fetching of the user_id cookie.
        Args:
            *args: Any number of positional arguments given as parameters.
            **kwargs: Any number of keyword arguments given as parameters to the function.
        """
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        user_id = self.get_verified_cookie('user_id')
        # set self.user to the user, provided it exists and is valid
        self.user = user_id and User.fetch_by_id(int(user_id))
        if self.user:
            self.set_session(self.user)

    @staticmethod
    def set_session(user=None):
        """A function that passes general user information to the session global variable 
            within the jinja2 environment, so that it is available within templates.
        Args:
            user: The Datastore User entity of the currently logged in user.
        """
        if not user:
            jinja_env.globals['session'] = {}
        else:
            jinja_env.globals['session'].update({'id': user.key.id(),
                                                 'username': user.username,
                                                 'email': user.email})

    @staticmethod
    def fetch_session_notification():
        """Copies the current notification (if any) from the jinja global session 
            variable, sets the global to None, and then returns the message."""
        user_message = jinja_env.globals['session'].get('notification')
        # reset the session notification global value to None.
        jinja_env.globals['session']['notification'] = None
        return user_message


class MainPage(BlogHandler):
    """Displays the main introduction page for The Big Borogu."""
    def get(self):
        self.render('introduction.html')


class BlogFront(BlogHandler):
    """Displays a page that lists the 10 latest posts on The Big Borogu."""
    def get(self):
        posts = ndb.gql("select * from Post order by created desc limit 10")
        user_message = self.fetch_session_notification()
        self.render('front.html', posts=posts, user_message=user_message)


class PostPage(BlogHandler):
    """Displays the chosen post, with functionality for liking, disliking, user
        following, post deletion and editing (only user creator) and post commenting.
    """
    def get(self, urlsafe_postkey):
        post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
        if not post:
            self.error(404)
            return
        user_message = self.fetch_session_notification()
        # if GET request received for post, which matches creator name, like post.
        if self.request.get('like_status') and self.request.get('target_user'):
            if self.user and self.user.username != post.creator:
                user_message = self.like_post(str(self.request.get('like_status')),
                                              int(self.user.key.id()), urlsafe_postkey)
                post.process_like(post, str(self.request.get('like_status')))
            elif self.user and self.user.username == post.creator:
                user_message = {'title': 'Whoops!',
                                'text': 'You cannot like your own post!',
                                'image': 'thumbs-down.jpg'
                                }
            else:
                user_message = {'title': 'Whoops!',
                                'text': 'You must be logged in to like a post!',
                                'image': 'thumbs-down.jpg'
                                }
        # if GET request received for comment deletion, verify user and delete.
        if self.request.get('delete_comment') and self.request.get('comment_user'):
            if str(self.user.username) == str(self.request.get('comment_user')):
                post.delete_comment(int(self.request.get('comment_num')), self.user.username)
                post.put()

        if self.user:
            creator = True if self.user.username == post.creator else False
            user = User.fetch_by_id(self.user.key.id())
            liked_post = 'liked' if user.is_liked_post(urlsafe_postkey) else False
            liked_post = 'disliked' if user.is_liked_post(urlsafe_postkey, dislike=True) else liked_post
            return self.render("permalink.html", post=post, creator=creator,
                               liked_post=liked_post, user_message=user_message)
        else:
            return self.render("permalink.html", post=post,
                               creator=False, user_message=user_message)

    def post(self, urlsafe_postkey):
        post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
        if not post:
            self.error(404)
            return
        comment = self.request.get('comment')
        commenter = self.request.get('comment-user')
        alert_message = None
        if self.user:
            creator = True if self.user.username == post.creator else False
            user = User.fetch_by_id(self.user.key.id())
            liked_post = 'liked' if user.is_liked_post(urlsafe_postkey) else False
            liked_post = 'disliked' if user.is_liked_post(urlsafe_postkey, dislike=True) else liked_post
            if not comment or not commenter:
                alert_message = {'title': "Whoops!",
                                 'text': "You need to fill in the comment field and must be logged in!",
                                 'type': "error"}
                return self.render("permalink.html", post=post, creator=creator,
                                   liked_post=liked_post, alert_message=alert_message)
            else:
                post.comments.append((commenter, comment))
                post.put()
                self.redirect('/blog/{0}'.format(urlsafe_postkey))
        else:
            alert_message = {'title': "Whoops!",
                             'text': "You need to be logged in to comment!",
                             'type': "error"}
            return self.render("permalink.html", post=post, alert_message=alert_message)

    def like_post(self, like_status, user_id, urlsafe_postkey):
        if self.user and int(self.user.key.id()) == int(user_id):
            user = User.fetch_by_id(self.user.key.id())
            if str(like_status) == "like":
                user.like_post(urlsafe_postkey)
                msg_text = 'You liked this post.'
            elif str(like_status) == "unlike":
                user.like_post(urlsafe_postkey, unlike=True)
                msg_text = 'You no longer like this post.'
            elif str(like_status) == "dislike":
                user.dislike_post(urlsafe_postkey)
                msg_text = 'This post has been disliked.'
            elif str(like_status) == "undislike":
                user.dislike_post(urlsafe_postkey, undislike=True)
                msg_text = 'You no longer dislike this post.'
            else:
                msg_text = 'Something went wrong, sorry.'

            user_message = {'title': 'Thanks!',
                            'text': msg_text,
                            'image': 'thumbs-up.jpg'
                            }
            return user_message
        else:
            raise KeyError("The session user id does not match the user liking!")


class UserPosts(BlogHandler):
    """Displays all of a users created posts."""
    def get(self, user_id):
        if self.user and int(self.user.key.id()) == int(user_id):
            user_posts = Post.query_post(self.user.key).fetch()
            # fetch all user liked/disliked posts using the User liked_post_keys string list.
            liked_keys = [ndb.Key(urlsafe=i) for i in self.user.liked_post_keys[-10:]]
            disliked_keys = [ndb.Key(urlsafe=i) for i in self.user.disliked_post_keys[-10:]]
            liked_posts = ndb.get_multi(liked_keys)
            disliked_posts = ndb.get_multi(disliked_keys)
            followed_keys = [ndb.Key(urlsafe=i) for i in self.user.followed_user_keys[:25]]
            followers = ndb.get_multi(followed_keys)
            return self.render("userposts.html", user_posts=user_posts,
                               liked_posts=liked_posts, followers=followers)
        else:
            self.redirect("/login")


class NewPost(BlogHandler):
    """Blog post creation page, whereby a User can create their own rich text blog post."""

    def get(self, user_id):
        if self.user and int(self.user.key.id()) == int(user_id):
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self, user_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=self.user.key, subject=subject,
                     content=content, creator=self.user.username)
            p.put()
            # create a urlsafe version of the key and pass into URL.
            self.redirect('/blog/%s' % str(p.key.urlsafe()))
        else:
            alert_message = {'title': "Whoops!",
                             'text': "You need to fill in both subject and content!",
                             'type': "error"}
            self.render("newpost.html", subject=subject,
                        content=content, alert_message=alert_message)


class EditPost(BlogHandler):
    """A page for editing a created blog post, provided the user is the original
        creator."""

    def get(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                self.render('editpost.html', post=post)
            else:
                error = "You must be the post owner in order to edit!"
                self.redirect("/blog/{0}".format(str(urlsafe_postkey)))
        else:
            self.redirect("/login")

    def post(self, urlsafe_postkey):
        post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
        if not post:
            self.error(404)
            return
        if self.user and self.user.username == post.creator:
            new_subject = self.request.get('subject')
            new_content = self.request.get('content-area')
            post.subject, post.content = str(new_subject), str(new_content)
            post.put()
            jinja_env.globals['session']['notification'] = {
                'title': 'Thanks {0}'.format(self.user.username),
                'text': 'Your blog post has been successfully updated.',
                'image': 'thumbs-up.jpg'}
            self.redirect("/blog")
        else:
            raise KeyError("A User who is not the creator cannot edit a post.")


class DeletePost(BlogHandler):
    """A page for deletion of the chosen blog post, provided the logged in user is
        the original post creator."""

    def get(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                self.render('deletepost.html', post=post)
            else:
                raise KeyError("A User who is not the creator cannot delete a post.")
        else:
            self.redirect("/login")

    def post(self, urlsafe_postkey):
        if self.user:
            post = ndb.Key(urlsafe=str(urlsafe_postkey)).get()
            if self.user.username == post.creator:
                delete_request = self.request.get('deletePost')
                if delete_request == "yes":
                    post.key.delete()
                    jinja_env.globals['session']['notification'] = {
                        'title': 'Thanks {0}'.format(self.user.username),
                        'text': 'Your blog post has been successfully deleted.',
                        'image': 'thumbs-up.jpg'
                    }
                    self.redirect("/blog")
                elif delete_request == "no":
                    self.redirect("/blog/{0}".format(str(post_id)))
                else:
                    self.redirect("/blog/{0}".format(str(post_id)))
            else:
                raise KeyError("A User who is not the creator cannot delete a post.")
        else:
            self.redirect("/login")


class Signup(BlogHandler):
    """A signup page for user registration, which performs verification and validation
        on the user input parameters. Returns an error notification if not formatted
        correctly."""

    def get(self):
        # obtain any user_messages passed into the notification var, and reset to None.
        alert_message = jinja_env.globals['session'].get('notification')
        jinja_env.globals['session']['notification'] = None
        self.render("signup.html", alert_message=alert_message)

    def post(self):
        have_error, alert_message = False, {}
        username = str(self.request.get('username')).capitalize()
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        # check for an existing username with the same name, if so, insert error
        q = User.query()
        q = q.filter(User.username == username).get()
        if q:
            params['error_name_taken'] = "That username is already taken!"
            have_error = True

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            # generate error messages for errors that have been highlighted.
            gen = (v for (k, v) in params.iteritems() if k.startswith('error'))
            msg_text = ""
            for entry in gen:
                msg_text += "{0} ".format(str(entry))
                alert_message = {'title': "Whoops!", 'text': msg_text, 'type': "error"}
            self.render('signup.html', alert_message=alert_message, **params)
        else:
            user = User.new_user(username=username, password=password, email=email)
            user.put()
            self.login(str(user.key.id()))
            self.redirect('/welcome')


class Login(BlogHandler):
    """A page for existing user login. Validates the input user credentials against
        those stored within Datastore and returns a notification message, dependent
        on successful login or error."""

    def get(self):
        self.render('login.html')

    def post(self):
        have_error = False
        username = str(self.request.get('username')).capitalize()
        password = self.request.get('password')

        params = dict(username=username)

        # attempt to fetch the user corresponding to the username from the database.
        user = User.fetch_by_username(username)
        # generate an error message if user does not exist.
        if not user:
            have_error = True
            params['error_username'] = "We couldn't find a user with that username."
            if not password:
                have_error = True
                params['error_password'] = "You need to enter a password!"
        # if user does exist, validate the given password against the User password hash.
        else:
            pass_val = valid_user_password(username, password, str(user.pass_hash))
            if not pass_val:
                have_error = True
                params['error_password'] = "The password you entered was incorrect."

        if have_error:
            gen = (v for (k, v) in params.iteritems() if k.startswith('error'))
            msg_text = ""
            for entry in gen:
                msg_text += "{0} ".format(str(entry))
            alert_message = {'title': "Whoops!",
                             'text': msg_text,
                             'type': "error"}
            self.render('login.html', alert_message=alert_message, **params)
        else:
            # log the user in using the BlogHandler method login:
            self.login(str(user.key.id()))
            self.redirect('/welcome')


class Logout(BlogHandler):
    """ A BlogHandler class for User logout. Logs the current user out and returns a
        notification message alerting the user to successful logout."""

    def get(self):
        user_id = self.get_verified_cookie('user_id')
        self.logout()
        # obtain any user_messages passed into the notification var, and reset to None.
        jinja_env.globals['session']['notification'] = {'title': "Your logout was successful!",
                                                        'text': "Thank you for taking the time to visit!",
                                                        'type': "success"}
        self.redirect('/signup')


class Welcome(BlogHandler):
    """ A welcome page for the logged in User, which acts as a portal to other applcation
        features, such as post viewing and account settings."""

    def get(self):
        # ensure the user_id secure cookie has not been tampered with and it exists
        user_id = self.get_verified_cookie('user_id')
        # ensure the user_id secure cookie has not been tampered with and it exists
        if not user_id:
            self.redirect('/signup')
        # ensure the user_id secure cookie has not been tampered with
        user = User.fetch_by_id(int(user_id))
        if not user:
            raise ValueError("The stored user_id cookie matches no registered user.")
        self.render('welcome.html', username=user.username)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               # blog individual page, using int regular expression for post id.
                               # Within handler urls, we pass in parameters using parenthesis (parameter).
                               ('/blog/([a-zA-Z0-9-_]+)', PostPage),
                               ('/user/([0-9]+)/newpost', NewPost),
                               ('/user/([0-9]+)', UserPosts),
                               ('/blog/([a-zA-Z0-9-_]+)/edit', EditPost),
                               ('/blog/([a-zA-Z0-9-_]+)/delete', DeletePost),
                               ],
                              debug=True)
