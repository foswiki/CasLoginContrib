# Module of Foswiki Collaboration Platform, http://Foswiki.org/
#
# Copyright (C) 2012 Sven Dowideit, SvenDowideit@fosiki.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.

=pod

---+ package Foswiki::LoginManager::CasLogin

The CasLogin class uses the CAS SSO to auto-login into Foswiki

=cut

package Foswiki::LoginManager::CasLogin;

use strict;
use Assert;
use Foswiki::LoginManager::TemplateLogin;
use Foswiki::Func;
use AuthCAS;

@Foswiki::LoginManager::CasLogin::ISA =
  ('Foswiki::LoginManager::TemplateLogin');

sub new {
    my ( $class, $session ) = @_;

    my $this = bless( $class->SUPER::new($session), $class );
    $session->enterContext('can_login');

    $this->{CAS} = new AuthCAS(
        casUrl      => $Foswiki::cfg{CAS}{casUrl},
        CAFile      => $Foswiki::cfg{CAS}{CAFile},
        SSL_version => $Foswiki::cfg{CAS}{SSL_version}
    );

    return $this;
}

sub finish {
    my $this = shift;

    undef $this->{CAS};

    $this->SUPER::finish();
    return;
}

=pod

---++ ObjectMethod loadSession()


=cut

sub loadSession {
    my $this    = shift;
    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};

    my $ticket = $query->param('ticket');

    ASSERT( $this->isa('Foswiki::LoginManager::CasLogin') ) if DEBUG;

    if ( $query->param('logout') && $Foswiki::cfg{CAS}{LogoutFromCAS} ) {

#can't redirect browser to logout from CAS, as the CAS server does not return to service URL
#$foswiki->redirect($this->logoutUrl(), 0);
        $this->{CAS}->callCAS( $this->logoutUrl() );
    }

# LoginManager::loadSession does a redirect on logout, so we have to deal with (CAS) logout before it.
    my $authUser = $this->SUPER::loadSession();

    #print STDERR "hello : $authUser\n";
    #print STDERR "params: ".join(', ', $query->param())."\n";
    #print STDERR "uri: ".Foswiki::Func::getUrlHost().$query->uri()."\n";
    #check returned ticket
    if ( defined($ticket) ) {
        my $uri = Foswiki::Func::getUrlHost() . $query->uri();
        $uri =~ s/[?;&]ticket=.*$//;
        $authUser = $this->{CAS}->validateST( $uri, $ticket );

        #        print STDERR "login? $authUser => $ticket\n";
        #TODO: protect against auth as basemapper admin?

       #if its an email address, we can make the generated wikiname more usefull
        $authUser =~ s/(\.|@)(.)/$1.uc($2)/ge;
        $authUser = ucfirst($authUser);

        $this->userLoggedIn($authUser);
        my $origurl = $query->param('foswiki_origin');
    }
    else {
        if (   defined( $query->param('sudo') )
            || defined( $query->param('logout') ) )
        {

            #sudo-ing, allow template auth
            $authUser = $Foswiki::cfg{DefaultUserLogin};
            $this->userLoggedIn($authUser);
        }
        else {
            if ( $foswiki->inContext('login') ) {
                $this->forceAuthentication();
            }
        }
    }

    return $authUser;
}

=begin TML

---++ ObjectMethod forceAuthentication () -> $boolean

method called when authentication is required - redirects to (...|view)auth
Triggered on auth fail

=cut

sub forceAuthentication {
    my $this    = shift;
    my $session = $this->{session};

    if ( !$session->inContext('authenticated') && !defined($query->param('ticket'))) {
        $session->redirect( $this->loginUrl(), 0 );
        return 1;
    }
    return 0;
}

=begin TML

---++ ObjectMethod loginUrl () -> $loginUrl

over-ride the login url

=cut

sub loginUrl {
    my $this = shift;

    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};
    my $uri     = Foswiki::Func::getUrlHost() . $query->uri();

    #remove any urlparams, as they will be in the cachedQuery
    $uri =~ s/\?.*$//;
    return $this->{CAS}->getServerLoginURL(
        Foswiki::urlEncode( $uri . $foswiki->cacheQuery() ) );
}

=begin TML

---++ ObjectMethod logoutUrl () -> $loginUrl

can't over-ride the logout url yet, but will try to use it.

=cut

sub logoutUrl {
    my $this = shift;

    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};
    my $uri     = Foswiki::Func::getUrlHost() . $query->uri();

    #remove any urlparams, as they will be in the cachedQuery
    $uri =~ s/\?.*$//;
    return $this->{CAS}->getServerLogoutURL(
        Foswiki::urlEncode( $uri . $foswiki->cacheQuery() ) );
}

1;
