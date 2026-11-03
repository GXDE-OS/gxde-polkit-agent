/*
 * Copyright (C) 2026 CharOfString <root@charofstring.cc>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DEEPINAUTHCHECK_H
#define DEEPINAUTHCHECK_H

#include <QString>
#include <QStringList>

// Deepin authentication (fingerprint, and passwords checked by
// dde-authority) hands polkit a one-time cookie instead of the password.
// Only pam_deepin_auth.so in the polkit-1 stack accepts that cookie, so
// without it every authentication, password included, would fail.

// Directories Linux-PAM looks in for a service, in order.
QStringList PamSearchDirs();

// Whether the auth stack of `service` reaches `module` (e.g.
// "pam_deepin_auth.so"), following @include, include and substack.
bool PamAuthStackHasModule(const QString &service, const QString &module,
                           const QStringList &dirs = PamSearchDirs());

// dde-authority is reachable on the system bus and polkit-1 accepts its
// cookies.
bool DeepinAuthAvailable();

#endif // DEEPINAUTHCHECK_H
