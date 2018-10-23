## A simple wrapper for the http.Client type ##

This wrapper provides some convenience methods for stuff I tend to add a lot to the default http.Client  
It also provides a default client with some sensible timeout defaults set.

It can:
* Disable server certificate validation
* Set a proxy to use
* Add custom CA certificates to validate certificates provided by remote servers
* Add client certificates to present to remote servers