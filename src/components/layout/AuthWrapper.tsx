
import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { motion } from 'framer-motion';

interface AuthWrapperProps {
  children: ReactNode;
  title: string;
  subtitle?: string;
  className?: string;
}

const AuthWrapper = ({ children, title, subtitle, className }: AuthWrapperProps) => {
  return (
    <div className="min-h-screen w-full flex flex-col md:flex-row">
      {/* Left side - Illustration/Branding */}
      <div className="hidden md:flex md:w-1/2 bg-gradient-to-br from-primary/90 to-tertiary/90 text-white p-8 flex-col justify-between">
        <div className="h-full flex flex-col justify-center items-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="text-center"
          >
            <h1 className="text-4xl font-bold mb-4">SecureDoc</h1>
            <p className="text-xl mb-8 max-w-md opacity-90">
              Secure document storage and sharing with intuitive design and premium experience
            </p>
            
            {/* Decorative elements */}
            <div className="relative mt-12">
              <motion.div 
                className="absolute w-40 h-40 rounded-2xl bg-white/10 backdrop-blur-md border border-white/20 -top-4 -left-8 z-10"
                animate={{ 
                  y: [0, -10, 0],
                  rotate: [0, 5, 0]
                }}
                transition={{ 
                  duration: 6,
                  repeat: Infinity,
                  repeatType: "reverse" 
                }}
              />
              <motion.div 
                className="relative w-64 h-64 rounded-2xl bg-white/20 backdrop-blur-md border border-white/30 z-20 flex items-center justify-center"
                animate={{ 
                  y: [0, 10, 0],
                  rotate: [0, -5, 0]
                }}
                transition={{ 
                  duration: 7, 
                  repeat: Infinity,
                  repeatType: "reverse"
                }}
              >
                <motion.div 
                  className="w-32 h-40 rounded-xl bg-white/30 backdrop-blur-lg border border-white/40 flex items-center justify-center"
                  animate={{ 
                    scale: [1, 1.05, 1],
                    rotate: [0, 2, 0]
                  }}
                  transition={{ 
                    duration: 5, 
                    repeat: Infinity,
                    repeatType: "reverse"
                  }}
                >
                  <svg 
                    viewBox="0 0 24 24" 
                    fill="none" 
                    stroke="currentColor" 
                    className="w-12 h-12 opacity-90"
                  >
                    <path 
                      d="M14 3v4a1 1 0 0 0 1 1h4" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                      strokeLinejoin="round"
                    />
                    <path 
                      d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2z" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                      strokeLinejoin="round"
                    />
                    <path 
                      d="M9 9h1" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                    />
                    <path 
                      d="M9 13h6" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                    />
                    <path 
                      d="M9 17h6" 
                      strokeWidth="2" 
                      strokeLinecap="round" 
                    />
                  </svg>
                </motion.div>
              </motion.div>
              <motion.div 
                className="absolute w-36 h-36 rounded-full bg-white/10 backdrop-blur-sm border border-white/10 top-16 -right-10 z-0"
                animate={{ 
                  y: [0, 15, 0],
                  x: [0, 10, 0],
                  rotate: [0, 10, 0]
                }}
                transition={{ 
                  duration: 8, 
                  repeat: Infinity,
                  repeatType: "reverse"
                }}
              />
            </div>
          </motion.div>
        </div>
        
        <div className="text-sm opacity-70 text-center pt-8">
          &copy; {new Date().getFullYear()} SecureDoc • Designed by Anish Ghimire
        </div>
      </div>
      
      {/* Right side - Auth Form */}
      <div className={cn(
        "w-full md:w-1/2 flex flex-col justify-center items-center p-6 md:p-12",
        className
      )}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="w-full max-w-md"
        >
          <h2 className="text-3xl font-bold mb-2">{title}</h2>
          {subtitle && <p className="text-muted-foreground mb-8">{subtitle}</p>}
          {children}
        </motion.div>
      </div>
    </div>
  );
};

export default AuthWrapper;
