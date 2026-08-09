import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Overlay } from './Overlay';
import { SettingsOverlay } from './SettingsOverlay';

type MenuPage = 'settings' | 'guide' | 'about' | 'mission' | 'contact' | null;

const MENU_ITEMS: Array<{ id: NonNullable<MenuPage>; labelKey: string; titleKey: string; contentKey: string }> = [
  { id: 'guide', labelKey: 'menu.guide', titleKey: 'menu.guideTitle', contentKey: 'menu.guideContent' },
  { id: 'about', labelKey: 'menu.about', titleKey: 'menu.aboutTitle', contentKey: 'menu.aboutContent' },
  { id: 'mission', labelKey: 'menu.mission', titleKey: 'menu.missionTitle', contentKey: 'menu.missionContent' },
  { id: 'contact', labelKey: 'menu.contact', titleKey: 'menu.contactTitle', contentKey: 'menu.contactContent' },
];

interface MenuOverlayProps {
  onClose: () => void;
}

export function MenuOverlay({ onClose }: MenuOverlayProps) {
  const { t } = useTranslation();
  const [page, setPage] = useState<MenuPage>(null);

  if (page === 'settings') {
    return <SettingsOverlay onClose={onClose} onBack={() => setPage(null)} />;
  }

  const activeItem = MENU_ITEMS.find((item) => item.id === page);

  return (
    <Overlay
      title={activeItem ? t(activeItem.titleKey) : t('menu.title')}
      onClose={onClose}
      onBack={activeItem ? () => setPage(null) : undefined}
    >
      {!activeItem && (
        <ul className="overlay-list">
          <li>
            <button type="button" className="overlay-list__item overlay-list__item--nav" onClick={() => setPage('settings')}>
              <span>{t('settings.openLabel')}</span>
              <span aria-hidden="true">›</span>
            </button>
          </li>
          {MENU_ITEMS.map((item) => (
            <li key={item.id}>
              <button type="button" className="overlay-list__item overlay-list__item--nav" onClick={() => setPage(item.id)}>
                <span>{t(item.labelKey)}</span>
                <span aria-hidden="true">›</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {activeItem && (
        <div className="overlay-content">
          {t(activeItem.contentKey)
            .split('\n')
            .map((line, index) => (
              <p key={index} className={line === line.toUpperCase() && line.trim().length > 2 ? 'overlay-content__heading' : undefined}>
                {line || ' '}
              </p>
            ))}
        </div>
      )}
    </Overlay>
  );
}
