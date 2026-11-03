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

#include "deepinauthcheck.h"

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QTextStream>

namespace {

const char kAuthorityService[] = "com.deepin.daemon.Authority";
const char kPolkitService[] = "polkit-1";
const char kDeepinAuthModule[] = "pam_deepin_auth.so";
const int kMaxIncludeDepth = 16;

QString findService(const QString &service, const QStringList &dirs)
{
    if (service.isEmpty() || service.contains(QLatin1Char('/')))
        return QFileInfo(service).isFile() ? service : QString();
    for (const QString &dir : dirs) {
        const QString path = QDir(dir).filePath(service);
        if (QFileInfo(path).isFile())
            return path;
    }
    return QString();
}

// Logical lines: comments removed, backslash continuations joined.
QStringList readLines(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return {};
    QStringList lines;
    QString pending;
    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine();
        const int hash = line.indexOf(QLatin1Char('#'));
        if (hash >= 0)
            line.truncate(hash);
        if (line.endsWith(QLatin1Char('\\'))) {
            line.chop(1);
            pending += line + QLatin1Char(' ');
            continue;
        }
        pending += line;
        lines << pending.trimmed();
        pending.clear();
    }
    if (!pending.trimmed().isEmpty())
        lines << pending.trimmed();
    return lines;
}

bool hasModule(const QString &service, const QString &module,
               const QStringList &dirs, int depth)
{
    if (depth > kMaxIncludeDepth)
        return false;
    const QString path = findService(service, dirs);
    if (path.isEmpty())
        return false;

    static const QRegularExpression space(QStringLiteral("\\s+"));
    for (const QString &line : readLines(path)) {
        if (line.isEmpty())
            continue;
        QStringList tokens = line.split(space);  // line is trimmed: no empty parts
        if (tokens.first() == QLatin1String("@include")) {
            if (tokens.size() > 1 && hasModule(tokens.at(1), module, dirs, depth + 1))
                return true;
            continue;
        }
        QString type = tokens.takeFirst();
        if (type.startsWith(QLatin1Char('-')))
            type.remove(0, 1);
        if (type.compare(QLatin1String("auth"), Qt::CaseInsensitive) != 0 || tokens.isEmpty())
            continue;

        // The control field may be a bracketed list containing spaces.
        QString control = tokens.takeFirst();
        if (control.startsWith(QLatin1Char('['))) {
            while (!control.endsWith(QLatin1Char(']')) && !tokens.isEmpty())
                control += QLatin1Char(' ') + tokens.takeFirst();
        }
        if (tokens.isEmpty())
            continue;
        const QString target = tokens.first();

        if (control == QLatin1String("include") || control == QLatin1String("substack")) {
            if (hasModule(target, module, dirs, depth + 1))
                return true;
        } else if (QFileInfo(target).fileName() == module) {
            return true;
        }
    }
    return false;
}

} // namespace

QStringList PamSearchDirs()
{
    return {QStringLiteral("/etc/pam.d"), QStringLiteral("/usr/lib/pam.d"),
            QStringLiteral("/usr/share/pam.d")};
}

bool PamAuthStackHasModule(const QString &service, const QString &module,
                           const QStringList &dirs)
{
    return hasModule(service, module, dirs, 0);
}

bool DeepinAuthAvailable()
{
    const QString authority = QString::fromLatin1(kAuthorityService);
    QDBusConnectionInterface *bus = QDBusConnection::systemBus().interface();
    const bool authorityAvailable = bus
        && (bus->isServiceRegistered(authority).value()
            || bus->activatableServiceNames().value().contains(authority));
    const bool pamAcceptsCookie = PamAuthStackHasModule(
        QString::fromLatin1(kPolkitService), QString::fromLatin1(kDeepinAuthModule));

    qDebug() << "Deepin auth: authority" << authorityAvailable
             << "pam_deepin_auth in polkit-1" << pamAcceptsCookie;
    return authorityAvailable && pamAcceptsCookie;
}
