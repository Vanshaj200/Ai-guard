"use client"
import React, { useEffect, useState } from 'react'
import Header from '@/components/Header'
import Sidebar from '@/components/Sidebar'
import GlobalSearchModal from '@/components/GlobalSearchModal'

export default function ClientLayout({ children }: { children: React.ReactNode }) {
  const [isSearchOpen, setIsSearchOpen] = useState(false)

  // Global ⌘K / Ctrl+K shortcut advertised in the header search bar
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setIsSearchOpen(open => !open)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="flex flex-col min-h-screen">
      <Header onOpenSearch={() => setIsSearchOpen(true)} />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
      <GlobalSearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </div>
  )
}
