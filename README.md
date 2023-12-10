# Groove50
#### Video Demo:  <https://youtu.be/tQucDoNOW50?si=IbHNrBcy4o2ZUutA>
#### Description:
> **A social media application written in Flask that leverages the [Spotify Web API](https://developer.spotify.com/documentation/web-api)**

## Key Features

- **Spotify Integration:** Groove50 offers seamless Spotify integration, enabling users to link their Spotify accounts. This connection allows users to showcase a preferred playlist on their profile, reveal follower counts, display their Spotify username, and provide a direct link to their Spotify account.

- **Groups:** Within Groove50, users have the ability to establish new groups or become members of existing ones. These groups serve as collaborative spaces where members can exchange songs and albums. Additionally, users can engage in discussions by commenting on each other's posts, fostering a dynamic and interactive music-sharing community.

- **Search:** Groove50 simplifies user exploration through a comprehensive search feature. Users can effortlessly search for other individuals or groups, granting them easy access to profiles and content. This feature enhances the overall user experience, promoting discovery and connection within the Groove50 community.

- **Activity Feed:** Groove50 compiles posts from all the groups you're part of, presenting them chronologically on the website's homepage as they are shared.

## Implementation Details

#### Technologies Used

- **[Flask](https://flask.palletsprojects.com/en/3.0.x/):** The backend of the application is powered by Flask, a lightweight and flexible Python web framework.

- **[Spotify Web API](https://developer.spotify.com/documentation/web-api):** Integration with the Spotify platform is achieved through the Spotify Web API, allowing seamless access to music-related data.

- **[OAuth 2.0](https://oauth.net/2/):** The application utilizes the OAuth 2.0 authorization framework to securely authenticate and obtain user consent for accessing private information.

- **[Bootstrap](https://getbootstrap.com/):** For front-end development, Bootstrap is employed to ensure a responsive and visually appealing user interface.

- **[Jinja Templating](https://jinja.palletsprojects.com/en/3.1.x/):** Dynamic content rendering is facilitated by Jinja templating, allowing seamless integration of Python code within HTML templates.

The **[Spotify Web API](https://developer.spotify.com/documentation/web-api)** uses the **[OAuth2.0 authorization framework](https://oauth.net/2/)**.  To obtain access to users' private information, the application has been developed utilizing the  **[Authorization Code Flow](https://developer.spotify.com/documentation/web-api/tutorials/code-flow)**.

## Files

 -  **app.py** - defines the routes and endpoints of the app and handles submissions

 - **helpers.py** - defines helper functions that are used in **app.py**

 - **templates/** - all the templates rendered in the app

 - **static/** - a CSS file where styling apart from bootstrap is done and a favicon.ico file

 - **groove.db** - sqlite3 file where all the data are stored
    - database tables
        - users
        - profile_playlist_id
        - groups
        - group_members
        - posts
        - comments
