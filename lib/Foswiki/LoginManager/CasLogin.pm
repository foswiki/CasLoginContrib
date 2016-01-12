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

        $this->userLoggedIn( $Foswiki::cfg{DefaultUserLogin} );
        $foswiki->redirect( $this->logoutUrl(), 0 );

#can't callCAS - this only happens in the background from foswiki server, and does not result in a CAS logout
#presumably because the logout must be initiated by the user
#$this->{CAS}->callCAS( $this->logoutUrl() );
    }

# LoginManager::loadSession does a redirect on logout, so we have to deal with (CAS) logout before it.
    my $authUser = $this->SUPER::loadSession(@_);
    my $uri      = Foswiki::Func::getUrlHost() . $query->uri();

    #print STDERR "hello : $authUser\n";
    #print STDERR "params: ".join(', ', $query->param())."\n";
    #print STDERR "uri: $uri\n";
    #print STDERR "relative ".$query->url(-relative=>1);
    #print STDERR "full ".$query->url(-full=>1);
    #print STDERR "query ".$query->url(-query=>1);
    #check returned ticket
    if ( defined($ticket) ) {
        $uri =~ s/[?;&]ticket=.*$//;
        my $casUser = $this->{CAS}->validateST( $uri, $ticket );
        if ($casUser) {
            if (   $Foswiki::cfg{CAS}{AllowLoginUsingEmailAddress}
                && $casUser =~ /@/ )
            {
                my $login = $foswiki->{users}->findUserByEmail($casUser);
                $casUser = $login->[0] if ( defined( $login->[0] ) );
            }

            $authUser = $casUser;
            $this->userLoggedIn($authUser);
        }
        else {

 # a bad ticket - so ignore
 # its a bit difficult if its a resubmit of an old ticket to the login script :/
        }
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
            if ( $foswiki->inContext('login') || $foswiki->inContext('logon') )
            {
                if ( !$this->forceAuthentication() ) {
                    my $full = $query->url( -full => 1 );
                    $uri =~ s/^$full//;
                    $uri = Foswiki::Func::getScriptUrl( undef, undef, 'view' )
                      . $uri;
                    $foswiki->redirect( $uri, 0 );
                }
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
    my $query   = $session->{request};

    if (   !$session->inContext('authenticated')
        && !defined( $query->param('ticket') ) )
    {
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
