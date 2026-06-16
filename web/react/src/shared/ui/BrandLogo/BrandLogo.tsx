import './BrandLogo.css'

type Props = {
  size?: 'sm' | 'md'
  showTitle?: boolean
  className?: string
}

export function BrandLogo({ size = 'md', showTitle = true, className = '' }: Props) {
  const iconSize = size === 'sm' ? 18 : 22

  return (
    <div className={`brand-logo ${size === 'sm' ? 'brand-logo-sm' : ''} ${className}`.trim()}>
      <div className="brand-logo-mark" aria-hidden="true">
        <img src="/logo.svg" alt="" width={iconSize} height={iconSize} draggable={false} />
      </div>
      {showTitle && <span className="brand-logo-title">DAST</span>}
    </div>
  )
}
