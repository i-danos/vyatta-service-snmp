#!/usr/bin/perl
#
# Copyright (c) 2017-2019, AT&T Intellectual Property.
# Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
# Copyright (c) 2007-2010 Vyatta, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

use strict;
use warnings;

foreach my $name (@ARGV) {
    die "$name : illegal characters in name\n"
	if (!($name =~ /^[a-zA-Z0-9]*$/));

    # Usernames may only be up to 32 characters long.
    die "$name: name may only be up to 32 characters long\n"
	if (length($name) > 32);
}

exit 0;
